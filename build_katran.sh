#!/usr/bin/env bash

if [ -f /etc/redhat-release ]; then
  ./build_katran_centos.sh
else
  ./build_katran_ubuntu.sh
fi

