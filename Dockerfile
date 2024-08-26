FROM mcr.microsoft.com/cbl-mariner/base/core:2.0

RUN tdnf install ethtool vim openssh-server git mariner-repos-extended WALinuxAgent cloud-init ca-certificates wget double-conversion libmnl libdwarf elfutils  -y

# build_katran.sh things
RUN tdnf install cmake git elfutils-libelf-devel libmnl xz-devel re2-devel libatomic libsodium fmt -y 
RUN tdnf install -y \
            boost-devel \
            boost-static \
            lz4-devel \
            xz-devel \
            snappy-devel \
            zlib-devel \
            zlib-static \
            glog \
            python3 \
            openssl-devel \
            elfutils-devel elfutils-devel-static \
            libunwind-devel \
            bzip2-devel \
            binutils-devel \
            clang \
            flex \ 
            golang

# libkrb5-dev \ required for fbthrift not found
# epel-release not found
# uninstall glog?