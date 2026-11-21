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

# this script will start simple_katran_server w/ xdproot
set -xeo pipefail

if [ -z "${KATRAN_INTERFACE}" ]
then
    KATRAN_INTERFACE=enp0s3
fi

# By default this script assumes to be invoked from the root dir, with the
# CMake build in build/, or the deprecated build_katran.sh's in _build/build.
# build/ also ships fbcode_builder, so look for a CMake cache, not the directory.
if [ -z "${KATRAN_BUILD_DIR}" ]
then
    KATRAN_BUILD_DIR=$(pwd)/build
    if [ ! -f "${KATRAN_BUILD_DIR}/CMakeCache.txt" ] && [ -f "$(pwd)/_build/build/CMakeCache.txt" ]
    then
        KATRAN_BUILD_DIR=$(pwd)/_build/build
    fi
fi

KATRAN_BUILD_DIR="${KATRAN_BUILD_DIR}" KATRAN_INTERFACE="${KATRAN_INTERFACE}" ./install_xdproot.sh
sudo sh -c "${KATRAN_BUILD_DIR}/example/simple_katran_server -balancer_prog=${KATRAN_BUILD_DIR}/bpf/balancer.bpf.o -intf=${KATRAN_INTERFACE} -hc_forwarding=false -map_path=/sys/fs/bpf/jmp_${KATRAN_INTERFACE} -prog_pos=2"
