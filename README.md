# Fork

This is a fork, optimized for use on macOS and reverse-engineered for some documentation. It adds a library
written in standard C. It is based on the ARM assembly code from http://github.com/jocover/sha256-armv8 which
at the time this was written, had no license. All of my commits are subject to GPLv3 and my copyright.


Created by Jon-Erik Storm on 12/26/21.

Library based on jocover's sha256-armv8 assembly code.

Copyright (C) 2021, 2022 Jon-Erik G. Storm

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

The original author's README.md is below:

# SHA-256

This is a very basic implementation of a SHA-256 hash according to the [FIPS
180-4 standard](http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf)
in C. I did it for educational purposes, the code is not optimized at all, but
(almost) corresponds line by line to the standard.

The algorithm to process a small block of data is quite simple and very well
described in the standard. I found that correctly implementing the padding is
much harder.

It does not have any dependencies (except for the C standard library of course)
and can be compiled with `make`. When `sha256sum` is installed, a short test can
be run with `make test`.

Usage:

```
./main <input file>
```
