if(NOT BUILD_TESTS)
  return()
endif()

include(KatranTest)

add_library(base64_helpers STATIC
    utils/Base64Helpers.h
    utils/Base64Helpers.cpp
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
    tools/PcapParser.h
    tools/PcapParser.cpp
)

target_link_libraries(pcap_parser
    base64_helpers
    pcapwriter
    "Folly::folly"
    "glog::glog"
    "${BOOST_SYSTEM}"
)

add_library(bpftester STATIC
    framework/BpfTester.h
    framework/BpfTester.cpp
    tools/PacketBuilder.h
    tools/PacketBuilder.cpp
    fixtures/KatranBaseTestFixtures.h
    fixtures/KatranHCTestFixtures.h
    fixtures/KatranGueTestFixtures.h
    fixtures/KatranTPRTestFixtures.h
    fixtures/KatranIcmpTooBigTestFixtures.h
    fixtures/KatranLpmSrcLookupTestFixtures.h
    fixtures/KatranUdpFlowMigrationTestFixtures.h
)

target_link_libraries(bpftester
    "Folly::folly"
    "glog::glog"
    pcap_parser
    bpfadapter
)

katran_add_test(TARGET base64helpers-tests
  SOURCES
  utils/Base64Test.cpp
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
    utils/KatranTestProvision.h
    utils/KatranTestProvision.cpp
)

target_link_libraries(katran_test_provision
  katranlb
)

add_library(katran_test_util STATIC
    utils/KatranTestUtil.h
    utils/KatranTestUtil.cpp
)

target_link_libraries(katran_test_util
  katran_test_provision
  katranlb
  bpftester
)

# katran_tester is a 'standalone' integration test
add_executable(katran_tester framework/katran_tester.cpp)

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
