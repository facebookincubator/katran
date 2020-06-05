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

TOOLCHAIN_DIR=/opt/rh/devtoolset-8/root/usr/bin
if [[ -d "$TOOLCHAIN_DIR" ]]; then
    PATH="$TOOLCHAIN_DIR:$PATH"
fi

PROJECT_DIR=$(dirname "$0")
GETDEPS_PATHS=(
    "$PROJECT_DIR/build/fbcode_builder/getdeps.py"
    "$PROJECT_DIR/../../opensource/fbcode_builder/getdeps.py"
)

ROOT_DIR=$(pwd)
STAGE=${ROOT_DIR}/_build/
mkdir -p "$STAGE"

for getdeps in "${GETDEPS_PATHS[@]}"; do
    if [[ -x "$getdeps" ]]; then
        "$getdeps" build katran --current-project katran "$@"
        exit 0
    fi
done

echo "Could not find getdeps.py!?" >&2
exit 1
