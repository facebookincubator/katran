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
  -h|?                                           Show this help message
EOF
}

while getopts ":hp:i:m" arg; do
  case $arg in
    p)
      BUILD_DIR="${OPTARG}"
      ;;
    i)
      INSTALL_DIR="${OPTARG}"
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

get_dev_tools() {
    if [ -f /etc/redhat-release ]; then
        sudo yum install -y epel-release
        sudo yum-config-manager --enable PowerTools
        sudo yum groupinstall -y "Development Tools"
        sudo yum install -y cmake
    else
        sudo apt-get update
        sudo apt-get install -y   \
            build-essential       \
            cmake                 \
            libbison-dev          \
            bison                 \
            flex                  \
            bc                    \
            libbpfcc-dev
    fi
}

get_required_libs() {
    if [ -f /etc/redhat-release ]; then
        sudo yum install -y \
            git \
            elfutils-libelf-devel \
            libmnl-devel \
            xz-devel \
            re2-devel \
            libatomic-static \
            libsodium-static
    else
        sudo apt-get install -y    \
            libgoogle-glog-dev     \
            libgflags-dev          \
            libelf-dev             \
            libmnl-dev             \
            liblzma-dev            \
            libre2-dev
        sudo apt-get install -y libsodium-dev
    fi
}


get_libevent() {
    if [ ! -f /etc/redhat-release ]; then
        # not needed on ubuntu as it is available as a package
        return
    fi

    if [ -f "${DEPS_DIR}/libevent_installed" ]; then
        return
    fi

    EVENT_DIR=$DEPS_DIR/event
    EVENT_BUILD_DIR=$DEPS_DIR/event/_build
    rm -rf "$EVENT_DIR"
    pushd .
    echo -e "${COLOR_GREEN}[ INFO ] Cloning libevent repo ${COLOR_OFF}"
    git clone https://github.com/libevent/libevent --depth 1 --branch release-2.1.11-stable "$EVENT_DIR"
    echo -e "${COLOR_GREEN}[ INFO ] Building libevent ${COLOR_OFF}"
    mkdir -p "$EVENT_BUILD_DIR"
    cd "$EVENT_BUILD_DIR" || exit

    cmake -DEVENT__DISABLE_SAMPLES=on -DEVENT__DISABLE_TESTS=on -DCXX_STD=gnu++17       \
      -DCMAKE_BUILD_TYPE=RelWithDebInfo             \
      -DCMAKE_PREFIX_PATH="$INSTALL_DIR"            \
      -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR"         \
      ..

    make -j "$NCPUS"
    make install
    echo -e "${COLOR_GREEN}Libevent is installed ${COLOR_OFF}"
    popd
    touch "${DEPS_DIR}/libevent_installed"
}

get_gflags() {
    if [ ! -f /etc/redhat-release ]; then
        # not needed on ubuntu as it is available as a package
        return
    fi

    if [ -f "${DEPS_DIR}/gflags_installed" ]; then
        return
    fi
    GFLAGS_DIR=$DEPS_DIR/gflags
    GFLAGS_BUILD_DIR=$DEPS_DIR/gflags/_build
    rm -rf "$GFLAGS_DIR"
    pushd .
    echo -e "${COLOR_GREEN}[ INFO ] Cloning gflags repo ${COLOR_OFF}"
    git clone https://github.com/gflags/gflags --depth 1 --branch v2.2.2 "$GFLAGS_DIR"
    echo -e "${COLOR_GREEN}[ INFO ] Building gflags ${COLOR_OFF}"
    mkdir -p "$GFLAGS_BUILD_DIR"
    cd "$GFLAGS_BUILD_DIR" || exit

    cmake  -DCXX_STD=gnu++17                        \
      -DCMAKE_BUILD_TYPE=RelWithDebInfo             \
      -DCMAKE_PREFIX_PATH="$INSTALL_DIR"            \
      -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR"         \
      ..

    make -j "$NCPUS"
    make install
    echo -e "${COLOR_GREEN}Gflags is installed ${COLOR_OFF}"
    popd
    touch "${DEPS_DIR}/gflags_installed"
}

get_folly() {
    if [ -f "${DEPS_DIR}/folly_installed" ]; then
        return
    fi
    FOLLY_DIR=$DEPS_DIR/folly
    FOLLY_BUILD_DIR=$DEPS_DIR/folly/build

    rm -rf "$FOLLY_DIR"
    if [ -f /etc/redhat-release ]; then
        sudo yum install -y \
            boost-devel \
            boost-static \
            lz4-devel \
            xz-devel \
            snappy-devel \
            zlib-devel \
            zlib-static \
            glog-devel \
            python3-scons \
            double-conversion-devel \
            openssl-devel \
            libdwarf-devel \
            elfutils-devel elfutils-devel-static \
            libunwind-devel \
            bzip2-devel \
            binutils-devel
    else
        sudo apt-get install -y       \
            g++                       \
            automake                  \
            autoconf                  \
            autoconf-archive          \
            libtool                   \
            libboost-all-dev          \
            libevent-dev              \
            libdouble-conversion-dev  \
            libgoogle-glog-dev        \
            libgflags-dev             \
            liblz4-dev                \
            liblzma-dev               \
            libsnappy-dev             \
            make                      \
            zlib1g-dev                \
            binutils-dev              \
            libjemalloc-dev           \
            libssl-dev                \
            pkg-config                \
            libiberty-dev             \
            libunwind8-dev            \
            libdwarf-dev
    fi

    pushd .
    echo -e "${COLOR_GREEN}[ INFO ] Cloning folly repo ${COLOR_OFF}"
    git clone https://github.com/facebook/folly --depth 1 "$FOLLY_DIR"
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

get_clang() {
    if [ -f "${DEPS_DIR}/clang_installed" ]; then
        return
    fi

    if [ -f /etc/redhat-release ]; then
        sudo yum install -y clang llvm
    else
        CLANG_DIR=$DEPS_DIR/clang
        rm -rf "$CLANG_DIR"
        pushd .
        mkdir -p "$CLANG_DIR"
        cd "$CLANG_DIR"
        echo -e "${COLOR_GREEN}[ INFO ] Downloading Clang ${COLOR_OFF}"
        wget http://releases.llvm.org/8.0.0/clang+llvm-8.0.0-x86_64-linux-gnu-ubuntu-18.04.tar.xz
        tar xvf ./clang+llvm-8.0.0-x86_64-linux-gnu-ubuntu-18.04.tar.xz
        echo -e "${COLOR_GREEN}Clang is installed ${COLOR_OFF}"
        popd
    fi
    touch "${DEPS_DIR}/clang_installed"
}

get_gtest() {
    if [ -f "${DEPS_DIR}/googletest_installed" ]; then
        return
    fi
    GTEST_DIR=${DEPS_DIR}/googletest
    GTEST_BUILD_DIR=${DEPS_DIR}/googletest/build

    rm -rf "$GTEST_DIR"
    pushd .
    mkdir -p "$GTEST_DIR"
    cd "$GTEST_DIR"
    echo -e "${COLOR_GREEN}[ INFO ] Cloning googletest repo ${COLOR_OFF}"
    git clone --depth 1 https://github.com/google/googletest
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
    rm -rf "${MSTCH_DIR}"
    pushd .
    cd "${DEPS_DIR}"
    echo -e "${COLOR_GREEN}[ INFO ] Cloning mstch repo ${COLOR_OFF}"
    git clone --depth 1 https://github.com/no1msd/mstch
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
    rm -rf "${FIZZ_DIR}"
    pushd .
    echo -e "${COLOR_GREEN}[ INFO ] Cloning fizz repo ${COLOR_OFF}"
    git clone https://github.com/facebookincubator/fizz "$FIZZ_DIR"
    echo -e "${COLOR_GREEN}[ INFO ] install dependencies ${COLOR_OFF}"

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
    rm -rf "$WANGLE_DIR"
    pushd .
    cd "${DEPS_DIR}"
    echo -e "${COLOR_GREEN}[ INFO ] Cloning wangle repo ${COLOR_OFF}"
    git clone --depth 1 https://github.com/facebook/wangle "$WANGLE_DIR"
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
    rm -rf "$ZSTD_DIR"
    pushd .
    cd "$DEPS_DIR"
    echo -e "${COLOR_GREEN}[ INFO ] Cloning zstd repo ${COLOR_OFF}"
    git clone --depth 1 https://github.com/facebook/zstd --branch v1.3.7
    cd "$ZSTD_DIR"
    make -j "$NCPUS"
    sudo make install
    echo -e "${COLOR_GREEN}zstd is installed ${COLOR_OFF}"
    popd
    touch "${DEPS_DIR}/zstd_installed"
}

get_fmt() {
    if [ -f "$DEPS_DIR/fmt_installed" ]; then
        return
    fi
    FMT_DIR=$DEPS_DIR/fmt
    FMT_BUILD_DIR=$DEPS_DIR/fmt/build/
    rm -rf "$FMT_DIR"
    pushd .
    cd "$DEPS_DIR"
    echo -e "${COLOR_GREEN}[ INFO ] Cloning fmt repo ${COLOR_OFF}"
    git clone https://github.com/fmtlib/fmt
    mkdir -p "$FMT_BUILD_DIR"
    cd "$FMT_BUILD_DIR"
    cmake -DCXX_STD=gnu++17                         \
      -DCMAKE_BUILD_TYPE=RelWithDebInfo             \
      -DCMAKE_PREFIX_PATH="$INSTALL_DIR"            \
      -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR"         \
      ..
    make -j "$NCPUS"
    make install
    echo -e "${COLOR_GREEN}fmt is installed ${COLOR_OFF}"
    popd
    touch "$DEPS_DIR/fmt_installed"
}

get_fbthrift() {
    if [ -f "$DEPS_DIR/fbthrift_installed" ]; then
        return
    fi
    FBTHRIFT_DIR=$DEPS_DIR/fbthrift
    FBTHRIFT_BUILD_DIR=$DEPS_DIR/fbthrift/build/
    rm -rf "$FBTHRIFT_DIR"
    # install fb thrift specific deps
    sudo apt-get install -y \
        libkrb5-dev \
        flex
    pushd .
    cd "$DEPS_DIR"
    echo -e "${COLOR_GREEN}[ INFO ] Cloning fbthrift repo ${COLOR_OFF}"
    git clone --depth 1 https://github.com/facebook/fbthrift || true
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
    rm -rf "$RSOCKET_DIR"
    pushd .
    cd "$DEPS_DIR"
    echo -e "${COLOR_GREEN}[ INFO ] Cloning rsocket repo ${COLOR_OFF}"
    git clone --depth 1 https://github.com/rsocket/rsocket-cpp || true
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
    GO_INSTALLED=$(which go || true)
    if [ -z "$GO_INSTALLED" ]; then
        if [ -f /etc/centos-release ]; then
            sudo yum install -y golang
        else
            sudo apt-get install -y golang
        fi
    fi
    GRPC_DIR=$DEPS_DIR/grpc
    GRPC_BUILD_DIR=$DEPS_DIR/grpc/_build/
    rm -rf "$GRPC_DIR"
    pushd .
    cd "$DEPS_DIR"
    echo -e "${COLOR_GREEN}[ INFO ] Cloning grpc repo ${COLOR_OFF}"
    # pin specific release of grpc to avoid build failures
    # with new changes in grpc/absl
    git clone  --depth 1 https://github.com/grpc/grpc --branch v1.27.1
    # this is to deal with a nested dir
    cd grpc
    git submodule update --init
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
    rm -rf "${LIBBPF_DIR}"
    pushd .
    cd "${DEPS_DIR}"
    echo -e "${COLOR_GREEN}[ INFO ] Cloning libbpf repo ${COLOR_OFF}"
    git clone --depth 1 https://github.com/libbpf/libbpf || true
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

build_katran() {
    pushd .
    KATRAN_BUILD_DIR=$BUILD_DIR/build
    rm -rf "$KATRAN_BUILD_DIR"
    mkdir -p "$KATRAN_BUILD_DIR"

    cd "$KATRAN_BUILD_DIR" || exit
    LIB_BPF_PREFIX="$INSTALL_DIR"
    cmake -DCMAKE_PREFIX_PATH="$INSTALL_DIR"      \
      -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR"       \
      -DCMAKE_BUILD_TYPE=RelWithDebInfo           \
      -DPKG_CONFIG_USE_CMAKE_PREFIX_PATH=ON       \
      -DLIB_BPF_PREFIX="$LIB_BPF_PREFIX"          \
      -DBUILD_TESTS=On                            \
      ../..
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

get_dev_tools
get_required_libs
get_libevent
get_fmt
get_gflags
get_folly
get_clang
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
if [ -z "$INSTALL_DEPS_ONLY" ]; then
  build_katran
  test_katran
fi
