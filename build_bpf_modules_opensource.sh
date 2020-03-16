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

# By default it is called from the build dir.
# Optionally BUILD_DIR and SRC_DIR args can be supplied
usage() {
cat 1>&2 <<EOF

Usage ${0##*/} [-h|?] [-s SRC_DIR] [-b BUILD_DIR]
  -s SRC_DIR                     (optional): Path to source dir for katran
  -b BUILD_DIR                   (optional): Path to build dir for katran
  -h|?                                       Show this help message
EOF
}

while getopts ":hb:s:m" arg; do
  case $arg in
    b)
      BUILD_DIR="${OPTARG}"
      ;;
    s)
      SRC_DIR="${OPTARG}"
      ;;
    h) # Display help.
      usage
      exit 0
      ;;
  esac
done
shift $((OPTIND -1))

# Validate required parameters
if [ -z "${BUILD_DIR-}" ] ; then
  echo -e "[ INFO ] BUILD_DIR is not set. So setting it as default to $(pwd)"
  BUILD_DIR="$(pwd)/_build/"
fi

# Validate required parameters
if [ -z "${SRC_DIR-}" ] ; then
  echo -e "[ INFO ] SRC_DIR is not set. So setting it as default to $(pwd) "
  SRC_DIR="$(pwd)"
fi


CLANG_PATH="${BUILD_DIR}/deps/clang/clang+llvm-8.0.0-x86_64-linux-gnu-ubuntu-18.04"
if [ -f /etc/redhat-release ]; then
  CLANG_PATH=/usr
fi

rm -rf "${BUILD_DIR}/deps/bpfprog"
mkdir -p "${BUILD_DIR}/deps/bpfprog/include"
cp "${SRC_DIR}/katran/lib/Makefile-bpf" "${BUILD_DIR}/deps/bpfprog/Makefile"
cp -r "${SRC_DIR}/katran/lib/bpf" "${BUILD_DIR}/deps/bpfprog/"
cp -r "${SRC_DIR}/katran/decap/bpf" "${BUILD_DIR}/deps/bpfprog/"
cp "${SRC_DIR}"/katran/lib/linux_includes/* "${BUILD_DIR}/deps/bpfprog/include/"
cd "${BUILD_DIR}/deps/bpfprog" && LD_LIBRARY_PATH="${CLANG_PATH}/lib" make \
  EXTRA_CFLAGS="$*" \
  LLC="${CLANG_PATH}/bin/llc" CLANG="${CLANG_PATH}/bin/clang"
echo "BPF BUILD COMPLITED"
