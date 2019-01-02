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
INTERFACE="enp0s3"
./install_xdproot.sh
sudo sh -c "./build/example_grpc/katran_server_grpc -balancer_prog=./deps/bpfprog/bpf/balancer_kern.o -intf=${INTERFACE} -hc_forwarding=false -map_path=/sys/fs/bpf/jmp_${INTERFACE} -prog_pos=2"
