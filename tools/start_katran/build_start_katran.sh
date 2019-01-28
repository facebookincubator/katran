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

create_grpc_template () {
    rm -rf start_katran/src/start_katran/lb_katran
    mkdir -p start_katran/src/start_katran/lb_katran
    protoc -I ../../example_grpc/protos/ ../../example_grpc/protos/katran.proto --go_out=plugins=grpc:start_katran/src/start_katran/lb_katran
}

get_start_katran_deps() {
    pushd .
    cd start_katran/src/start_katran/main
    go get
    popd
}

build_start_katran() {
    pushd .
    cd start_katran/src/start_katran/main
    go build
    popd
}

echo """
Please make sure that go and grpc dependencies are installed
(
follow instructions @ https://grpc.io/docs/tutorials/basic/go.html
but TL;DR
go get -u google.golang.org/grpc
go get -u github.com/golang/protobuf/protoc-gen-go
)
This script will fail if go is not present
"""

go version 1>/dev/null
export GOPATH=$(pwd)/start_katran
create_grpc_template
get_start_katran_deps
build_start_katran
