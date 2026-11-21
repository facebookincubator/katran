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

sudo sh -c "${KATRAN_BUILD_DIR}/katran/lib/testing/katran_tester -balancer_prog ${KATRAN_BUILD_DIR}/bpf/balancer.bpf.o -test_from_fixtures=true $1"
