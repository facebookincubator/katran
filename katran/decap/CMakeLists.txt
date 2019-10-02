cmake_minimum_required (VERSION 3.9)
set(KATRAN_INCLUDE_DIR "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../>")

find_package(Glog REQUIRED)
find_package(folly CONFIG REQUIRED)
find_package(Threads)

add_library(decap STATIC
    XdpDecap.cpp
    XdpDecap.h
    XdpDecapStructs.h
)

target_link_libraries(decap
    bpfadapter
    "Folly::folly"
    glog::glog
)

target_include_directories(
  decap PUBLIC
  ${GFLAGS_INCLUDE_DIR}
  ${KATRAN_INCLUDE_DIR}
)

install(TARGETS decap
  EXPORT katran-exports
  DESTINATION decap
)

if (BUILD_TESTS)
  add_subdirectory(testing)
endif()
