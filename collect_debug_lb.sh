#!/usr/bin/env bash
 # Copyright (C) 2019-present, Facebook, Inc.
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
echo "### links ###"
ip link show
echo "### default route ###"
ip route show | grep default
echo "### neighbors ###"
ip neighbor show
echo "### ps ###"
ps ax  | grep katran
echo "### sysctl ###"
sysctl -a 2>&1 | grep bpf | grep -v denied
