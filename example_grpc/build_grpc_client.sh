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
rm -rf goclient/src/katranc/lb_katran
mkdir -p goclient/src/katranc/lb_katran
protoc -I protos katran.proto --go_out=plugins=grpc:goclient/src/katranc/lb_katran
}

get_goclient_deps() {
    pushd .
    cd goclient/src/katranc/main
    GO111MODULE=auto go get
    popd
}

build_goclient() {
    pushd .
    cd goclient/src/katranc/main
    GO111MODULE=auto go build
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
# fail hard if go is not installed
go version 1>/dev/null
export GOPATH=$(pwd)/goclient
create_grpc_template
get_goclient_deps
build_goclient
