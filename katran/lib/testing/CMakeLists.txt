if(NOT BUILD_TESTS)
  return()
endif()

include(KatranTest)

add_library(base64_helpers STATIC
    Base64Helpers.h
    Base64Helpers.cpp
)

target_link_libraries(base64_helpers
    "glog::glog"
    "${GFLAGS}"
    "Folly::folly"
    "${BOOST_SYSTEM}"
    "katranlb"
)

target_include_directories(
  base64_helpers PUBLIC
  "${GTEST_INCLUDE_DIR}"
  "${KATRAN_INCLUDE_DIR}"
)

add_library(pcap_parser STATIC
    PcapParser.h
    PcapParser.cpp
)

target_link_libraries(pcap_parser
    base64_helpers
    pcapwriter
    "Folly::folly"
    "glog::glog"
    "${BOOST_SYSTEM}"
)

add_library(bpftester STATIC
    BpfTester.h
    BpfTester.cpp
    KatranTestFixtures.h
    KatranHCTestFixtures.h
    KatranGueTestFixtures.h
    KatranOptionalTestFixtures.h
    KatranGueOptionalTestFixtures.h
)

target_link_libraries(bpftester
    "Folly::folly"
    "glog::glog"
    pcap_parser
    bpfadapter
)

katran_add_test(TARGET base64helpers-tests
  SOURCES
  Base64Test.cpp
  DEPENDS
  base64_helpers
  katranlb
  ${GTEST}
  "glog::glog"
  ${GFLAGS}
  "Folly::folly"
  ${LIBUNWIND}
  INCLUDES
  base64_helpers
)

add_library(katran_test_provision STATIC
    KatranTestProvision.h
    KatranTestProvision.cpp
)

target_link_libraries(katran_test_provision
  katranlb
)

add_library(katran_test_util STATIC
    KatranTestUtil.h
    KatranTestUtil.cpp
)

target_link_libraries(katran_test_util
  katran_test_provision
  katranlb
)

# katran_tester is a 'standalone' integration test
add_executable(katran_tester katran_tester.cpp)

target_link_libraries(katran_tester
  katranlb
  bpftester
  katran_test_provision
  katran_test_util
  ${GFLAGS}
  ${GTEST}
)

target_include_directories(katran_tester PRIVATE
  ${BPF_INCLUDE_DIRS}
  ${GTEST_INCLUDE_DIR}
  ${FOLLY_INCLUDE_DIR}
  ${KATRAN_INCLUDE_DIR}
)
