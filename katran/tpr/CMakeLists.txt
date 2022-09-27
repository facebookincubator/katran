cmake_minimum_required (VERSION 3.9)
set(KATRAN_TPR_INCLUDE_DIR "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../>")

find_package(Glog REQUIRED)
find_package(folly CONFIG REQUIRED)
find_package(Threads)

set(LIBBPF_INCLUDE_DIRS "${LIB_BPF_PREFIX}/include")
set(LIBBPF_LIBRARIES "${LIB_BPF_PREFIX}/lib")
set(BPFOBJECT_VMLINUX_H "bpf/vmlinux/vmlinux.h")
set(BPFOBJECT_BPFTOOL_EXE "${CMAKE_INSTALL_PREFIX}/bin/bpftool")
set(BPFOBJECT_EXTRA_DEFINES "-DKATRAN_CMAKE_BUILD")
find_package(BpfObject REQUIRED)

bpf_object(tpr_bpf
    bpf/tcp_pkt_router_kern.c

)

add_library(katran_tpr STATIC
    TPRStatsPoller.cpp
    TcpPktRouter.cpp
    TprBpfAdapter.cpp
)

target_compile_definitions(katran_tpr PUBLIC KATRAN_CMAKE_BUILD=1)

target_link_libraries(katran_tpr
    "Folly::folly"
    glog::glog
    ${BPF_LINK_LIBRARIES}
    tpr_bpf_skel
)

target_include_directories(
  katran_tpr PUBLIC
  ${GFLAGS_INCLUDE_DIR}
  ${KATRAN_TPR_INCLUDE_DIR}
)
