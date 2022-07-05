#!/bin/bash
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This script is just a simple wrapper around the
# build/fbcode_builder/getdeps.py script.
#
# Feel free to invoke getdeps.py directly to have more control over the build.

SCRIPT_DIR=$(dirname "${BASH_SOURCE[0]}")
GETDEPS_PATH="$SCRIPT_DIR/build/fbcode_builder/getdeps.py"
BUILD_DIR="$SCRIPT_DIR/_build/build"

install_deps() {
    sudo python3 "$GETDEPS_PATH" install-system-deps katran --recursive
}

build() {
    python3 "$GETDEPS_PATH" build katran "$@"
}

default_build() {
    build --allow-system-packages --build-dir "$BUILD_DIR"
}

case $1 in

  install) # installing required dependencies
    install_deps
    ;;

  "") # No argument, then it means we just do a default build
    default_build
    ;;

  *) # we redirect extra params to the getdeps.py build script
    build "$@"
    ;;

esac
