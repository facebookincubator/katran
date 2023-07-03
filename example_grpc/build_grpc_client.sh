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
protoc -I protos katran.proto --go_out=goclient/src/katranc/lb_katran --go_grpc_out=goclient/src/katranc/lb_katran
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
https://grpc.io/docs/protoc-installation/ for installing protoc
 but TL;DR
   apt install -y protobuf-compiler
   protoc --version  # Ensure compiler version is 3+
https://grpc.io/docs/languages/go/quickstart/ for installing grpc
 but TL;DR
   go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28
   go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2
   export PATH="$PATH:$(go env GOPATH)/bin"
)
This script will fail if go is not present

IMPORTANT:
If you get the following error:
protoc-gen-go_grpc: program not found or is not executable
Please specify a program using absolute path or make sure the program is available in your PATH system variable

And ls $(go env GOPATH)/bin/protoc-gen-go-grpc exists please do:
cp $(go env GOPATH)/bin/protoc-gen-go-grpc $(go env GOPATH)/bin/protoc-gen-go_grpc
"""
# fail hard if go or protoc is not installed
go version 1>/dev/null
protoc --version 1>/dev/null
# adding export paths
export GOPATH=$(pwd)/goclient
create_grpc_template
get_goclient_deps
build_goclient
