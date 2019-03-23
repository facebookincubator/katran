#!/usr/bin/env bash

 # Copyright (C) 2018-present, Facebook, Inc.
 #
 # This program is free software; you can redistribute it and/or modify
 # it under the terms of the GNU General Public License as published by
 # the Free Software Foundation; version 2 of the License.
 #
 # This program is distributed in the hope that it will be useful,
 # but WITHOUT ANY WARRANTY; without even the implied warranty of
 # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 # GNU General Public License for more details.
 #
 # You should have received a copy of the GNU General Public License along
 # with this program; if not, write to the Free Software Foundation, Inc.,
 # 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

set -xeo pipefail
# this script must be run inside katran's project root
# if you are adding new bpf prog:
# 1) put it into bpf/ dir
# 2) edit Makefile (add new prog into always += section)

CLANG_PATH="$(pwd)/deps/clang/clang+llvm-8.0.0-x86_64-linux-gnu-ubuntu-18.04"
rm -rf ./deps/bpfprog
mkdir -p ./deps/bpfprog/include
cp ./katran/lib/Makefile-bpf ./deps/bpfprog/Makefile
cp -r ./katran/lib/bpf ./deps/bpfprog/
cp -r ./katran/decap/bpf ./deps/bpfprog/
cp ./katran/lib/linux_includes/* ./deps/bpfprog/include/
cd ./deps/bpfprog && LD_LIBRARY_PATH="${CLANG_PATH}/lib" make \
  EXTRA_CFLAGS="$*" \
  LLC="${CLANG_PATH}/bin/llc" CLANG="${CLANG_PATH}/bin/clang"
echo "BPF BUILD COMPLITED"
