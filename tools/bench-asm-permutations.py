#!/usr/bin/env python3

import argparse
import csv
import itertools
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Tweaks:
    prefetch: bool
    countdown: bool
    trim_stack: bool
    align: bool
    state_load_pair: bool

    def tag(self) -> str:
        def b(x: bool) -> str:
            return "1" if x else "0"

        return f"pf{b(self.prefetch)}_cd{b(self.countdown)}_tr{b(self.trim_stack)}_al{b(self.align)}_ld{b(self.state_load_pair)}"


def run(cmd: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> str:
    proc = subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=True,
    )
    return proc.stdout


def must_find_once(lines: list[str], predicate, what: str) -> int:
    matches = [i for i, line in enumerate(lines) if predicate(line)]
    if len(matches) != 1:
        raise RuntimeError(f"expected exactly 1 match for {what}, got {len(matches)}")
    return matches[0]


def apply_align(lines: list[str]) -> list[str]:
    out = list(lines)

    label_i = must_find_once(out, lambda s: s.strip().endswith("_sha256_block_data_order:"), "function label")
    p2align_i = None
    for i in range(label_i - 1, -1, -1):
        if out[i].lstrip().startswith(".p2align"):
            p2align_i = i
            break
    if p2align_i is None:
        raise RuntimeError("failed to locate function .p2align")
    out[p2align_i] = re.sub(
        r"(\.p2align\s+)(\d+)",
        lambda m: f"{m.group(1)}5",
        out[p2align_i],
        count=1,
    )

    loop_i = must_find_once(out, lambda s: s.strip() == ".Lsha256loop:", "loop label")
    prev_i = loop_i - 1
    while prev_i >= 0 and out[prev_i].strip() == "":
        prev_i -= 1
    if prev_i < 0 or not out[prev_i].lstrip().startswith(".p2align"):
        out.insert(loop_i, "    .p2align  5\n")
    return out


def apply_prefetch(lines: list[str]) -> list[str]:
    out = []
    inserted = 0
    for line in lines:
        out.append(line)
        if "ld1" in line and "{v5.16b-v8.16b}" in line and "[x1]" in line and "#64" in line:
            out.append("    prfm      pldl1keep, [x1, #512]\n")
            inserted += 1
    if inserted != 1:
        raise RuntimeError(f"expected to insert prefetch once, inserted={inserted}")
    return out


def apply_countdown(lines: list[str]) -> list[str]:
    out = []
    removed_add = 0
    replaced_cmp = 0

    for line in lines:
        if "add" in line and "x2, x1, x2, lsl #6" in line:
            removed_add += 1
            continue
        if line.strip().startswith("cmp") and "x1" in line and "x2" in line:
            out.append("    subs      x2, x2, #1\n")
            replaced_cmp += 1
            continue
        out.append(line)

    if removed_add != 1:
        raise RuntimeError(f"expected to remove add x2 endptr once, removed={removed_add}")
    if replaced_cmp != 1:
        raise RuntimeError(f"expected to replace cmp once, replaced={replaced_cmp}")
    return out


def apply_trim_stack(lines: list[str]) -> list[str]:
    out = []
    replaced_stp = 0
    removed_mov = 0
    replaced_epilogue_pop = 0

    for line in lines:
        if "stp" in line and "x29" in line and "x30" in line and "[sp,#-64]!" in line:
            out.append("    sub       sp, sp, #48\n")
            replaced_stp += 1
            continue
        if line.strip().startswith("mov") and "x29" in line and "sp" in line:
            removed_mov += 1
            continue
        if "ldr" in line and "x29" in line and "[sp], #64" in line:
            out.append("    add       sp, sp, #48\n")
            replaced_epilogue_pop += 1
            continue

        line = line.replace("str       q8, [sp, #16]", "str       q8, [sp, #0]")
        line = line.replace("str       q9, [sp, #32]", "str       q9, [sp, #16]")
        line = line.replace("str       q10, [sp, #48]", "str       q10, [sp, #32]")

        line = line.replace("ldr       q10, [sp, #48]", "ldr       q10, [sp, #32]")
        line = line.replace("ldr       q9, [sp, #32]", "ldr       q9, [sp, #16]")
        line = line.replace("ldr       q8, [sp, #16]", "ldr       q8, [sp, #0]")

        out.append(line)

    # Allow no-op when the base file is already using the trimmed frame.
    if replaced_stp == 0:
        if not any("sub" in s and "sp, sp, #48" in s for s in out):
            raise RuntimeError("expected trimmed prologue (sub sp, sp, #48) or stp x29/x30")
    else:
        if replaced_stp != 1:
            raise RuntimeError(f"expected to replace stp x29/x30 once, replaced={replaced_stp}")
        if removed_mov != 1:
            raise RuntimeError(f"expected to remove mov x29, sp once, removed={removed_mov}")
        if replaced_epilogue_pop != 1:
            raise RuntimeError(f"expected to replace epilogue stack pop once, replaced={replaced_epilogue_pop}")
    return out


def apply_state_load_pair(lines: list[str]) -> list[str]:
    if any("{v0.4s,v1.4s}" in s and "[x0]" in s for s in lines):
        return list(lines)

    out = []
    replaced_v0 = 0
    removed_v1 = 0
    removed_sub = 0

    for line in lines:
        if "ld1" in line and "{v0.4s}" in line and "[x0], #16" in line:
            out.append("    ld1       {v0.4s,v1.4s}, [x0]\n")
            replaced_v0 += 1
            continue
        if line.strip().startswith("ld1") and "{v1.4s}" in line and "[x0]" in line:
            removed_v1 += 1
            continue
        if line.strip().startswith("sub") and "x0" in line and "#16" in line:
            removed_sub += 1
            continue
        out.append(line)

    if replaced_v0 != 1:
        raise RuntimeError(f"expected to replace v0 load once, replaced={replaced_v0}")
    if removed_v1 != 1:
        raise RuntimeError(f"expected to remove v1 load once, removed={removed_v1}")
    if removed_sub != 1:
        raise RuntimeError(f"expected to remove sub x0 once, removed={removed_sub}")
    return out


def apply_tweaks(base: list[str], tweaks: Tweaks) -> list[str]:
    lines = list(base)
    if tweaks.align:
        lines = apply_align(lines)
    if tweaks.trim_stack:
        lines = apply_trim_stack(lines)
    if tweaks.state_load_pair:
        lines = apply_state_load_pair(lines)
    if tweaks.countdown:
        lines = apply_countdown(lines)
    if tweaks.prefetch:
        lines = apply_prefetch(lines)
    return lines


BENCH_ROW_RE = re.compile(
    r"^\s*(\d+)\s+(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)x\s*$"
)


def parse_bench_output(text: str) -> dict[int, dict[str, float]]:
    rows: dict[int, dict[str, float]] = {}
    for line in text.splitlines():
        m = BENCH_ROW_RE.match(line)
        if not m:
            continue
        size = int(m.group(1))
        rows[size] = {
            "armv8": float(m.group(2)),
            "commoncrypto": float(m.group(3)),
            "speedup": float(m.group(4)),
        }
    if not rows:
        raise RuntimeError("failed to parse any benchmark rows")
    return rows


def metric(rows: dict[int, dict[str, float]]) -> float:
    # Focus on large-message throughput (1 MiB).
    return rows[1 << 20]["armv8"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--max", type=int, default=0, help="run only the first N variants (0 = all)")
    ap.add_argument("--repeats", type=int, default=1, help="benchmark repetitions per variant")
    args = ap.parse_args()

    if args.repeats < 1:
        raise SystemExit("--repeats must be >= 1")
    if args.max < 0:
        raise SystemExit("--max must be >= 0")

    repo = Path(__file__).resolve().parents[1]
    asm_path = repo / "sha256-armv8-aarch64.s"
    bench_c = repo / "tests" / "sha256-armv8-bench.c"
    wrapper_c = repo / "libsha256-armv8.c"

    base_lines = asm_path.read_text().splitlines(keepends=True)

    tweaks_list = list(
        itertools.product([False, True], repeat=5)
    )
    all_tweaks = [
        Tweaks(
            prefetch=pf,
            countdown=cd,
            trim_stack=tr,
            align=al,
            state_load_pair=ld,
        )
        for (pf, cd, tr, al, ld) in tweaks_list
    ]
    all_tweaks.sort(key=lambda t: t.tag())

    with tempfile.TemporaryDirectory(prefix="sha256-armv8-bench-") as td:
        tmp = Path(td)

        cflags = ["-O3", "-Wall", "-Wextra", "-Wpedantic", "-std=c11", f"-I{repo}"]

        print("building common objects...", file=sys.stderr)
        run(["clang", *cflags, "-c", str(wrapper_c), "-o", str(tmp / "wrapper.o")], cwd=repo)
        run(["clang", *cflags, "-c", str(bench_c), "-o", str(tmp / "bench.o")], cwd=repo)

        if args.max:
            all_tweaks = all_tweaks[: args.max]

        results = []
        for idx, tw in enumerate(all_tweaks, start=1):
            tag = tw.tag()
            variant_s = tmp / f"{tag}.s"
            variant_o = tmp / f"{tag}.o"
            bench_bin = tmp / f"bench-{tag}"

            variant_lines = apply_tweaks(base_lines, tw)
            variant_s.write_text("".join(variant_lines))

            run(["clang", "-c", str(variant_s), "-o", str(variant_o)], cwd=repo)
            run(["clang", str(tmp / "bench.o"), str(tmp / "wrapper.o"), str(variant_o), "-o", str(bench_bin)], cwd=repo)

            print(f"[{idx:02d}/{len(all_tweaks)}] {tag}", file=sys.stderr)
            reps = []
            for _ in range(args.repeats):
                out = run([str(bench_bin)], cwd=repo)
                reps.append(parse_bench_output(out))

            # Median by 1 MiB throughput; keep that run's full row set.
            reps.sort(key=lambda r: metric(r))
            rows = reps[len(reps) // 2]
            results.append({"tag": tag, "tweaks": tw, "rows": rows, "metric": metric(rows)})

        results.sort(key=lambda r: r["metric"], reverse=True)

        out_csv = repo / "bench-asm-permutations.csv"
        with out_csv.open("w", newline="") as f:
            w = csv.writer(f)
            w.writerow(
                [
                    "tag",
                    "prefetch",
                    "countdown",
                    "trim_stack",
                    "align",
                    "state_load_pair",
                    "armv8_mib_s_64",
                    "armv8_mib_s_8k",
                    "armv8_mib_s_64k",
                    "armv8_mib_s_1m",
                    "cc_mib_s_1m",
                    "speedup_1m",
                ]
            )
            for r in results:
                rows = r["rows"]
                w.writerow(
                    [
                        r["tag"],
                        int(r["tweaks"].prefetch),
                        int(r["tweaks"].countdown),
                        int(r["tweaks"].trim_stack),
                        int(r["tweaks"].align),
                        int(r["tweaks"].state_load_pair),
                        rows[64]["armv8"],
                        rows[8192]["armv8"],
                        rows[65536]["armv8"],
                        rows[1 << 20]["armv8"],
                        rows[1 << 20]["commoncrypto"],
                        rows[1 << 20]["speedup"],
                    ]
                )

        baseline = next(r for r in results if r["tag"] == Tweaks(False, False, False, False, False).tag())
        best = results[0]

        def fmt(r) -> str:
            m = r["rows"][1 << 20]["armv8"]
            b = baseline["rows"][1 << 20]["armv8"]
            pct = 100.0 * (m / b - 1.0)
            return f"{m:8.1f} MiB/s ({pct:+.2f}%)"

        print(f"baseline: {baseline['tag']}  {fmt(baseline)}")
        print(f"best:     {best['tag']}  {fmt(best)}")
        print(f"wrote:    {out_csv}")

        print("\nTop 10 (by 1 MiB throughput):")
        for r in results[:10]:
            print(f"{r['tag']}  {fmt(r)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
