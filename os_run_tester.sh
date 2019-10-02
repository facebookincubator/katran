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

# By default this script assumes to be invoked from the root dir.
if [ -z "${KATRAN_BUILD_DIR}" ]
then
    KATRAN_BUILD_DIR=$(pwd)/_build/build
fi

if [ -z "${DEPS_DIR}" ]
then
    DEPS_DIR=$(pwd)/_build/deps
fi

sudo sh -c "${KATRAN_BUILD_DIR}/katran/lib/testing/katran_tester -balancer_prog ${DEPS_DIR}/bpfprog/bpf/balancer_kern.o -test_from_fixtures=true $1"
sudo sh -c "${KATRAN_BUILD_DIR}/katran/decap/testing/xdpdecap_tester -decap_prog ${DEPS_DIR}/bpfprog/bpf/decap_kern.o -test_from_fixtures=true $1"
