cmake_minimum_required (VERSION 3.0)
project (libkatran-proj)

# for clang's compile_commands.json
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_COMPILER_ID "Clang")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++14")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Werror")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-sign-compare -Wno-bool-compare")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-error=unused-variable -Woverloaded-virtual -Wnon-virtual-dtor")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-maybe-uninitialized -Wdeprecated-declarations")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-error=deprecated-declarations")

# system libs
find_library(GLOG libglog.a glog)
find_library(LIBELF libelf.a elf)
find_library(LIBMNL libmnl.a mnl)
find_library(GFLAGS libgflags.a gflags)
find_library(GTEST gtest)
find_library(FOLLY libfolly.a folly)
find_library(PTHREAD pthread)
find_library(LIBUNWIND libunwind.a unwind)
find_library(LIBLZMA liblzma.a lzma)
find_library(LIBZ libz.a z)
find_library(LIBDC libdouble-conversion.a double-conversion)
find_library(BPF libbpf.a PATHS ${LIBBPF_PATH} NO_DEFAULT_PATH)
add_library(murmur3 STATIC
    MurmurHash3.h
    MurmurHash3.cpp
)

add_library(chhelpers STATIC
    CHHelpers.h
    CHHelpers.cpp
)

target_link_libraries(chhelpers murmur3)

add_library(iphelpers STATIC
    IpHelpers.h
    IpHelpers.cpp
)

target_link_libraries(iphelpers
    "${FOLLY}"
    "${LIBUNWIND}"
    "${LIBLZMA}"
    "${GLOG}"
    "${GFLAGS}"
    "${PTHREAD}"
    "${LIBDC}"
)

add_library(bpfadapter STATIC
    BpfAdapter.cpp
    BpfLoader.cpp
    BpfAdapter.h
    BpfLoader.h
    linux_includes/bpf.h
    linux_includes/bpf_common.h
    linux_includes/bpf_helpers.h
)

set(BPFADAPTER_DEPS
    "${BPF}"
    "${LIBUNWIND}"
    "${LIBLZMA}"
    "${GLOG}"
    "${PTHREAD}"
    "${LIBELF}"
    "${LIBZ}"
    "${LIBMNL}"
    "${FOLLY}"
    "${LIBDC}"
)

target_link_libraries(bpfadapter "${BPFADAPTER_DEPS}")
add_library(katranlb STATIC
    KatranLb.h
    KatranLb.cpp
    KatranLbStructs.h
    BalancerStructs.h
    Vip.h
    Vip.cpp
)

target_link_libraries(katranlb
    bpfadapter
    chhelpers
    iphelpers
    "${GFLAGS}"
)

add_library(mac_helpers STATIC
    MacHelpers.h
    MacHelpers.cpp
)

target_link_libraries(mac_helpers
    "${FOLLY}"
)

add_executable(xdproot xdproot.cpp)
target_link_libraries(xdproot
    bpfadapter
    "${GFLAGS}"
)

add_executable(maglev_integration_test maglev_integration_test.cpp)
target_link_libraries(maglev_integration_test
    chhelpers
    "${GFLAGS}"
    "${PTHREAD}"
)

add_subdirectory(testing)
add_subdirectory(tests)
