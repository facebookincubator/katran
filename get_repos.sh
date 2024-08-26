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
NCPUS=$(nproc)
# default to 4 threads for a reasonable build speed (e.g in travis)
if (( NCPUS < 4 )); then
  NCPUS=4
fi
ROOT_DIR=$(pwd)

# Useful constants
COLOR_RED="\033[0;31m"
COLOR_GREEN="\033[0;32m"
COLOR_OFF="\033[0m"

usage() {
cat 1>&2 <<EOF

Usage ${0##*/} [-h|?] [-p PATH] [-i INSTALL_DIR]
  -p BUILD_DIR                       (optional): Path to the base dir for katran
  -i INSTALL_DIR                     (optional): Install prefix path
  -v                                 (optional): make it verbose (even more)
  -h|?                                           Show this help message
EOF
}

while getopts ":hp:i:v" arg; do
  case $arg in
    p)
      BUILD_DIR="${OPTARG}"
      ;;
    i)
      INSTALL_DIR="${OPTARG}"
      ;;
    v)
      VERBOSE=1
      ;;
    h | *) # Display help.
      usage
      exit 0
      ;;
  esac
done

# Validate required parameters
if [ -z "${BUILD_DIR-}" ] ; then
  echo -e "${COLOR_RED}[ INFO ] Build dir is not set. So going to build into _build ${COLOR_OFF}"
  BUILD_DIR=${ROOT_DIR}/_build
  mkdir -p "$BUILD_DIR"
fi

cd "$BUILD_DIR" || exit
DEPS_DIR=$BUILD_DIR/deps
mkdir -p "$DEPS_DIR" || exit

if [ -z "${INSTALL_DIR-}" ] ; then
  echo -e "${COLOR_RED}[ INFO ] Install dir is not set. So going to install into ${DEPS_DIR} ${COLOR_OFF}"
  INSTALL_DIR=${DEPS_DIR}
  mkdir -p "$INSTALL_DIR"
fi

if [ -n "$FORCE_INSTALL" ]; then
    rm -rf ./deps
    rm -rf "$BUILD_DIR"
fi

if [ -n "$BUILD_EXAMPLE_THRIFT" ]; then
    BUILD_EXAMPLE_THRIFT=1
    export CMAKE_BUILD_EXAMPLE_THRIFT="$BUILD_EXAMPLE_THRIFT"
fi

if [ -z "$BUILD_EXAMPLE_GRPC" ]; then
    BUILD_EXAMPLE_GRPC=1
    export CMAKE_BUILD_EXAMPLE_GRPC="$BUILD_EXAMPLE_GRPC"
fi

if [ -n "$BUILD_TOOLS" ]; then
    BUILD_TOOLS=1
    export CMAKE_BUILD_TOOLS="$BUILD_TOOLS"
fi

if [ -n "$BUILD_KATRAN_TPR" ]; then
    BUILD_KATRAN_TPR=1
    export CMAKE_BUILD_KATRAN_TPR="$BUILD_KATRAN_TPR"
fi

get_folly() {
    FOLLY_DIR=$DEPS_DIR/folly
    FOLLY_BUILD_DIR=$DEPS_DIR/folly/build
    rm -rf "$FOLLY_DIR"
    pushd .
    echo -e "${COLOR_GREEN}[ INFO ] Cloning folly repo ${COLOR_OFF}"
    git clone https://github.com/facebook/folly --depth 1 "$FOLLY_DIR"
    popd
}

get_gtest() {
    GTEST_DIR=${DEPS_DIR}/googletest
    GTEST_BUILD_DIR=${DEPS_DIR}/googletest/build
    rm -rf "$GTEST_DIR"
    pushd .
    mkdir -p "$GTEST_DIR"
    cd "$GTEST_DIR"
    echo -e "${COLOR_GREEN}[ INFO ] Cloning googletest repo ${COLOR_OFF}"
    git clone --depth 1 https://github.com/google/googletest
    popd
}

get_mstch() {
    MSTCH_DIR=${DEPS_DIR}/mstch
    MSTCH_BUILD_DIR=${DEPS_DIR}/mstch/build
    rm -rf "${MSTCH_DIR}"
    pushd .
    cd "${DEPS_DIR}"
    echo -e "${COLOR_GREEN}[ INFO ] Cloning mstch repo ${COLOR_OFF}"
    git clone --depth 1 https://github.com/no1msd/mstch
    popd
}

get_fizz() {
    FIZZ_DIR=$DEPS_DIR/fizz
    FIZZ_BUILD_DIR=$DEPS_DIR/fizz/build/
    rm -rf "${FIZZ_DIR}"
    pushd .
    echo -e "${COLOR_GREEN}[ INFO ] Cloning fizz repo ${COLOR_OFF}"
    git clone https://github.com/facebookincubator/fizz "$FIZZ_DIR"
    popd
}

get_wangle() {
    WANGLE_DIR=$DEPS_DIR/wangle
    WANGLE_BUILD_DIR=$DEPS_DIR/wangle/build/
    rm -rf "$WANGLE_DIR"
    pushd .
    cd "${DEPS_DIR}"
    echo -e "${COLOR_GREEN}[ INFO ] Cloning wangle repo ${COLOR_OFF}"
    git clone --depth 1 https://github.com/facebook/wangle "$WANGLE_DIR"
    popd
}

get_zstd() {
    ZSTD_DIR=$DEPS_DIR/zstd
    rm -rf "$ZSTD_DIR"
    pushd .
    cd "$DEPS_DIR"
    echo -e "${COLOR_GREEN}[ INFO ] Cloning zstd repo ${COLOR_OFF}"
    git clone --depth 1 https://github.com/facebook/zstd --branch v1.3.7
    popd
}

get_fbthrift() {
    FBTHRIFT_DIR=$DEPS_DIR/fbthrift
    FBTHRIFT_BUILD_DIR=$DEPS_DIR/fbthrift/build/
    rm -rf "$FBTHRIFT_DIR"
    pushd .
    cd "$DEPS_DIR"
    echo -e "${COLOR_GREEN}[ INFO ] Cloning fbthrift repo ${COLOR_OFF}"
    git clone --depth 1 https://github.com/facebook/fbthrift || true
    popd
}

get_rsocket() {
    RSOCKET_DIR=$DEPS_DIR/rsocket-cpp
    RSOCKET_BUILD_DIR=$DEPS_DIR/rsocket-cpp/build/
    rm -rf "$RSOCKET_DIR"
    pushd .
    cd "$DEPS_DIR"
    echo -e "${COLOR_GREEN}[ INFO ] Cloning rsocket repo ${COLOR_OFF}"
    git clone --depth 1 https://github.com/rsocket/rsocket-cpp || true
    popd
}

get_grpc() {
    GRPC_DIR=$DEPS_DIR/grpc
    GRPC_BUILD_DIR=$DEPS_DIR/grpc/_build/
    rm -rf "$GRPC_DIR"
    pushd .
    cd "$DEPS_DIR"
    echo -e "${COLOR_GREEN}[ INFO ] Cloning grpc repo ${COLOR_OFF}"
    # pin specific release of grpc to avoid build failures
    # with new changes in grpc/absl
    git clone  --depth 1 https://github.com/grpc/grpc --branch v1.49.1
    # this is to deal with a nested dir
    cd grpc
    git submodule update --init
    popd
}

get_libbpf() {
    LIBBPF_DIR="${DEPS_DIR}/libbpf"
    rm -rf "${LIBBPF_DIR}"
    pushd .
    cd "${DEPS_DIR}"
    echo -e "${COLOR_GREEN}[ INFO ] Cloning libbpf repo ${COLOR_OFF}"
    git clone --depth 1 https://github.com/libbpf/libbpf || true
    popd
}

get_bpftool() {
    BPFTOOL_DIR="${DEPS_DIR}/bpftool"
    rm -rf "${BPFTOOL_DIR}"
    pushd .
    cd "${DEPS_DIR}"
    echo -e "${COLOR_GREEN}[ INFO ] Cloning bpftool repo ${COLOR_OFF}"
    git clone --recurse-submodules https://github.com/libbpf/bpftool.git || true
    popd
}


get_folly
get_gtest
get_libbpf
if [ "$BUILD_EXAMPLE_THRIFT" -eq 1 ]; then
  get_mstch
  get_fizz
  get_wangle
  get_zstd
  get_rsocket
  get_fbthrift
fi
if [ "$BUILD_EXAMPLE_GRPC" -eq 1 ]; then
  get_grpc
fi
if [ "$BUILD_KATRAN_TPR" -eq 1 ]; then
  get_bpftool
fi