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

# By default this script assumes to be invoked from the root dir.
if [ -z "${KATRAN_BUILD_DIR}" ]
then
    KATRAN_BUILD_DIR=$(pwd)/_build/build
fi

if [ -z "${DEPS_DIR}" ]
then
    DEPS_DIR=$(pwd)/_build/deps
fi

./install_xdproot.sh -b "${KATRAN_BUILD_DIR}" -d "${DEPS_DIR}"
sudo sh -c "${KATRAN_BUILD_DIR}/example/simple_katran_server -balancer_prog=${DEPS_DIR}/bpfprog/bpf/balancer_kern.o -intf=${KATRAN_INTERFACE} -hc_forwarding=false -map_path=/sys/fs/bpf/jmp_${KATRAN_INTERFACE} -prog_pos=2"
