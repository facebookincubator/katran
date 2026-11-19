add_library(bpf_util STATIC
    BpfUtil.cpp
)

target_compile_definitions(bpf_util PUBLIC KATRAN_CMAKE_BUILD=1)

target_link_libraries(bpf_util
    "Folly::folly"
    glog::glog
    ${BPF_LINK_LIBRARIES}
)

target_include_directories(
  bpf_util PUBLIC
  ${KATRAN_INCLUDE_DIR}
)
