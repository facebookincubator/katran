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
  ${LIBGFLAGS_INCLUDE_DIR}
  ${KATRAN_INCLUDE_DIR}
)

install(TARGETS decap
  EXPORT katran-exports
  DESTINATION decap
)

if (BUILD_TESTS)
  add_subdirectory(testing)
endif()
