add_subdirectory(bpf_util)

set(LIBBPF_INCLUDE_DIRS "${BPF_INCLUDEDIR}")
set(LIBBPF_LIBRARIES "${BPF_LINK_LIBRARIES}")
set(BPFOBJECT_VMLINUX_H "${CMAKE_CURRENT_SOURCE_DIR}/bpf/vmlinux.h")
set(BPFOBJECT_EXTRA_DEFINES "-DKATRAN_CMAKE_BUILD")
find_package(BpfObject REQUIRED)

bpf_object(tpr_bpf
    bpf/tcp_pkt_router.bpf.c

)

add_library(katran_tpr STATIC
    TPRStatsPoller.cpp
    TcpPktRouter.cpp
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
  ${LIBGFLAGS_INCLUDE_DIR}
  ${KATRAN_INCLUDE_DIR}
)

# TcpPktRouter.h includes the skeleton as tpr.skel.h.
add_custom_command(
  OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/tpr.skel.h"
  COMMAND "${CMAKE_COMMAND}" -E copy tpr_bpf.skel.h tpr.skel.h
  DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/tpr_bpf.skel.h"
)
target_sources(katran_tpr PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/tpr.skel.h")
