cmake_minimum_required (VERSION 3.9)
set(KATRAN_TPR_INCLUDE_DIR "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../../>")

find_package(Glog REQUIRED)
find_package(folly CONFIG REQUIRED)
find_package(Threads)

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
  ${GFLAGS_INCLUDE_DIR}
  ${KATRAN_TPR_INCLUDE_DIR}
)
