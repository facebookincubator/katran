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

# Example script to start and run xdproot program
set -xeo pipefail
INTERFACE="enp0s3"
out=$(mount | grep bpffs) || true
if [ -z "$out" ]; then
    sudo mount -t bpf bpffs /sys/fs/bpf/
fi

if [ ! -f "/sys/fs/bpf/jmp_${INTERFACE}" ]; then
    echo "Assuming ${INTERFACE} exists. please change script to actual interface if it does not"
    sudo sh -c "$(pwd)/build/katran/lib/xdproot -bpfprog $(pwd)/deps/bpfprog/bpf/xdp_root.o -bpfpath=/sys/fs/bpf/jmp_${INTERFACE} -intf=${INTERFACE}"
fi
