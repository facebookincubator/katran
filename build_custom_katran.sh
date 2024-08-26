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
    if [ -f "${DEPS_DIR}/folly_installed" ]; then
        return
    fi
    FOLLY_DIR=$DEPS_DIR/folly
    FOLLY_BUILD_DIR=$DEPS_DIR/folly/build
    pushd .
    echo -e "${COLOR_GREEN}[ INFO ] Building Folly ${COLOR_OFF}"
    mkdir -p "$FOLLY_BUILD_DIR"
    cd "$FOLLY_BUILD_DIR" || exit

    cmake  -DCXX_STD=gnu++17                        \
      -DCMAKE_BUILD_TYPE=RelWithDebInfo             \
      -DCMAKE_PREFIX_PATH="$INSTALL_DIR"            \
      -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR"         \
      ..
    make -j "$NCPUS"
    make install
    echo -e "${COLOR_GREEN}Folly is installed ${COLOR_OFF}"
    popd
    touch "${DEPS_DIR}/folly_installed"
}

get_gtest() {
    if [ -f "${DEPS_DIR}/googletest_installed" ]; then
        return
    fi
    GTEST_DIR=${DEPS_DIR}/googletest
    GTEST_BUILD_DIR=${DEPS_DIR}/googletest/build
    pushd .
    cd "$GTEST_DIR"
    mkdir -p "$GTEST_BUILD_DIR"
    cd "$GTEST_BUILD_DIR"
    cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo         \
      -DCMAKE_PREFIX_PATH="$INSTALL_DIR"            \
      -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR"         \
      ../googletest
    make install
    echo -e "${COLOR_GREEN}googletest is installed ${COLOR_OFF}"
    popd
    touch "${DEPS_DIR}/googletest_installed"
}

get_mstch() {
    if [ -f "${DEPS_DIR}/mstch_installed" ]; then
        return
    fi
    MSTCH_DIR=${DEPS_DIR}/mstch
    MSTCH_BUILD_DIR=${DEPS_DIR}/mstch/build
    pushd .
    cd "${DEPS_DIR}"
    mkdir -p "${MSTCH_BUILD_DIR}"
    cd "${MSTCH_BUILD_DIR}" || exit
    cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo         \
      -DCMAKE_PREFIX_PATH="$INSTALL_DIR"            \
      -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR"         \
      ..
    make -j "$NCPUS"
    make install
    popd
    echo -e "${COLOR_GREEN}mstch is installed ${COLOR_OFF}"
    touch "${DEPS_DIR}/mstch_installed"
}

get_fizz() {
    if [ -f "${DEPS_DIR}/fizz_installed" ]; then
        return
    fi
    FIZZ_DIR=$DEPS_DIR/fizz
    FIZZ_BUILD_DIR=$DEPS_DIR/fizz/build/
    pushd .
    echo -e "${COLOR_GREEN}Building Fizz ${COLOR_OFF}"
    mkdir -p "$FIZZ_BUILD_DIR"
    cd "$FIZZ_BUILD_DIR" || exit
    cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo       \
      -DCMAKE_PREFIX_PATH="$INSTALL_DIR"     \
      -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR"  \
      -DBUILD_TESTS=OFF                      \
      "$FIZZ_DIR/fizz"
    make -j "$NCPUS"
    make install
    echo -e "${COLOR_GREEN}Fizz is installed ${COLOR_OFF}"
    popd
    echo -e "${COLOR_GREEN}Fizz is installed ${COLOR_OFF}"
    touch "${DEPS_DIR}/fizz_installed"
}

get_wangle() {
    if [ -f "${DEPS_DIR}/wangle_installed" ]; then
        return
    fi
    WANGLE_DIR=$DEPS_DIR/wangle
    WANGLE_BUILD_DIR=$DEPS_DIR/wangle/build/
    pushd .
    cd "${DEPS_DIR}"
    mkdir -p "$WANGLE_BUILD_DIR"
    cd "$WANGLE_BUILD_DIR" || exit
    echo -e "${COLOR_GREEN}Building Wangle ${COLOR_OFF}"
    cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo         \
      -DCMAKE_PREFIX_PATH="$INSTALL_DIR"            \
      -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR"         \
      ../wangle
    make -j "$NCPUS"
    make install
    echo -e "${COLOR_GREEN}wangle is installed ${COLOR_OFF}"
    popd
    touch "${DEPS_DIR}/wangle_installed"
}

get_zstd() {
    if [ -f "${DEPS_DIR}/zstd_installed" ]; then
        return
    fi
    ZSTD_DIR=$DEPS_DIR/zstd
    pushd .
    cd "$DEPS_DIR"
    cd "$ZSTD_DIR"
    make -j "$NCPUS"
    sudo make install
    echo -e "${COLOR_GREEN}zstd is installed ${COLOR_OFF}"
    popd
    touch "${DEPS_DIR}/zstd_installed"
}

get_fbthrift() {
    if [ -f "$DEPS_DIR/fbthrift_installed" ]; then
        return
    fi
    FBTHRIFT_DIR=$DEPS_DIR/fbthrift
    FBTHRIFT_BUILD_DIR=$DEPS_DIR/fbthrift/build/
    pushd .
    cd "$DEPS_DIR"
    mkdir -p "$FBTHRIFT_BUILD_DIR"
    cd "$FBTHRIFT_BUILD_DIR"
    cmake -DCXX_STD=gnu++17                         \
      -DCMAKE_BUILD_TYPE=RelWithDebInfo             \
      -DCMAKE_PREFIX_PATH="$INSTALL_DIR"            \
      -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR"         \
      ..

    make -j "$NCPUS"
    make install
    echo -e "${COLOR_GREEN}fbthrift is installed ${COLOR_OFF}"
    popd
    touch "$DEPS_DIR/fbthrift_installed"
}

get_rsocket() {
    if [ -f "$DEPS_DIR/rsocket_installed" ]; then
        return
    fi
    RSOCKET_DIR=$DEPS_DIR/rsocket-cpp
    RSOCKET_BUILD_DIR=$DEPS_DIR/rsocket-cpp/build/
    pushd .
    cd "$DEPS_DIR"
    mkdir -p "$RSOCKET_BUILD_DIR"
    cd "$RSOCKET_BUILD_DIR" || exit
    cmake -DCXX_STD=gnu++17                         \
      -DCMAKE_BUILD_TYPE=RelWithDebInfo             \
      -DCMAKE_PREFIX_PATH="$INSTALL_DIR"            \
      -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR"         \
      ..
    make -j "$NCPUS"
    make install
    echo -e "${COLOR_GREEN}rsocket is installed ${COLOR_OFF}"
    popd
    touch "$DEPS_DIR/rsocket_installed"
}

get_grpc() {
    if [ -f "${DEPS_DIR}/grpc_installed" ]; then
        return
    fi
    GRPC_DIR=$DEPS_DIR/grpc
    GRPC_BUILD_DIR=$DEPS_DIR/grpc/_build/
    pushd .
    cd "$DEPS_DIR"
    cd grpc
    mkdir -p "$GRPC_BUILD_DIR"
    cd "$GRPC_BUILD_DIR" || exit
    cmake -DCXX_STD=gnu++17                         \
      -DCMAKE_CXX_FLAGS=-Wno-unused-result          \
      -DCMAKE_BUILD_TYPE=RelWithDebInfo             \
      -DCMAKE_PREFIX_PATH="$INSTALL_DIR"            \
      -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR"         \
      -DgRPC_BUILD_GRPC_CSHARP_PLUGIN=OFF           \
      -DgRPC_BUILD_GRPC_NODE_PLUGIN=OFF             \
      -DgRPC_BUILD_GRPC_OBJECTIVE_C_PLUGIN=OFF      \
      -DgRPC_BUILD_GRPC_PHP_PLUGIN=OFF              \
      -DgRPC_BUILD_GRPC_RUBY_PLUGIN=OFF             \
      ..

    make -j "$NCPUS"
    make install
    cd "$GRPC_DIR"/third_party/protobuf
    make && make install
    echo -e "${COLOR_GREEN}grpc is installed ${COLOR_OFF}"
    popd
    touch "${DEPS_DIR}/grpc_installed"
}

get_libbpf() {
    if [ -f "${DEPS_DIR}/libbpf_installed" ]; then
        return
    fi
    LIBBPF_DIR="${DEPS_DIR}/libbpf"
    pushd .
    cd "${DEPS_DIR}"
    cd "${LIBBPF_DIR}"/src
    make
    #on centos the cp -fpR used was throwing an error, so just use a regular cp -R
    if [ -f /etc/redhat-release ]; then
        sed -i 's/cp -fpR/cp -R/g' Makefile
    fi
    DESTDIR="$INSTALL_DIR" make install
    cd "$LIBBPF_DIR"
    cp -r include/uapi "$INSTALL_DIR"/usr/include/bpf/
    cd "$INSTALL_DIR"/usr/include/bpf
    # override to use local bpf.h instead of system wide
    sed -i 's/#include <linux\/bpf.h>/#include <bpf\/uapi\/linux\/bpf.h>/g' ./bpf.h
    sed -i 's/#include <linux\/bpf.h>/#include <bpf\/uapi\/linux\/bpf.h>/g' ./libbpf.h
    sed -i 's/#include <linux\/bpf.h>/#include <bpf\/uapi\/linux\/bpf.h>/g' ./libbpf_legacy.h
    # Move to CMAKE_PREFIX_PATH so that cmake can easily discover them
    cd "$INSTALL_DIR"
    mv "$INSTALL_DIR"/usr/include/bpf "$INSTALL_DIR"/include/
    cp -r "$INSTALL_DIR"/usr/lib64/* "$INSTALL_DIR"/lib/
    echo -e "${COLOR_GREEN}libbpf is installed ${COLOR_OFF}"
    popd
    touch "${DEPS_DIR}/libbpf_installed"
}

get_bpftool() {
    if [ -f "${DEPS_DIR}/bpftool_installed" ]; then
        return
    fi
    BPFTOOL_DIR="${DEPS_DIR}/bpftool"
    pushd .
    cd "${DEPS_DIR}"
    cd "${BPFTOOL_DIR}"/src
    make
    cp "${BPFTOOL_DIR}"/src/bpftool "${INSTALL_DIR}/bin/bpftool"
    echo -e "${COLOR_GREEN}bpftool is installed ${COLOR_OFF}"
    popd
    touch "${DEPS_DIR}/bpftool_installed"
}


build_katran() {
    pushd .
    KATRAN_BUILD_DIR=$BUILD_DIR/build
    rm -rf "$KATRAN_BUILD_DIR"
    mkdir -p "$KATRAN_BUILD_DIR"

    cd "$KATRAN_BUILD_DIR" || exit
    LIB_BPF_PREFIX="$INSTALL_DIR"

    # Base set of CMake flags
    CMAKE_FLAGS="-DCMAKE_PREFIX_PATH=$INSTALL_DIR \
    -DCMAKE_INSTALL_PREFIX=$INSTALL_DIR \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DPKG_CONFIG_USE_CMAKE_PREFIX_PATH=ON \
    -DLIB_BPF_PREFIX=$LIB_BPF_PREFIX \
    -DCMAKE_CXX_STANDARD=17 \
    -DBUILD_TESTS=On"

    # Append verbose flag if VERBOSE is set to 1
    if [ "$VERBOSE" -eq 1 ]; then
        CMAKE_FLAGS="$CMAKE_FLAGS -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON"
    fi

    # Run CMake with the constructed flags
    cmake $CMAKE_FLAGS ../..

    make -j "$NCPUS"
    popd
    "${ROOT_DIR}"/build_bpf_modules_opensource.sh \
        -s "${ROOT_DIR}"                          \
        -b "${BUILD_DIR}"                         \
        2>/dev/null
}

test_katran() {
    pushd .
    cd "$BUILD_DIR"/build/katran/lib/tests/
    ctest -v ./*
    cd ../testing/
    ctest -v ./*
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
if [ -z "$INSTALL_DEPS_ONLY" ]; then
  build_katran
  test_katran
fi
