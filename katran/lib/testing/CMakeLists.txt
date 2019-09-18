# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

cmake_minimum_required (VERSION 3.0)
project(libkatran_testing)
find_library(GTEST gtest)

# find libs
find_package(folly CONFIG REQUIRED)
find_library(GTEST gtest)
find_path(GTEST_INCLUDE_DIR gtest)
find_library(BOOST_SYSTEM libboost_system.a boost_system)

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

add_library(xdptester STATIC
    XdpTester.h
    XdpTester.cpp
    KatranTestFixtures.h
    KatranOptionalTestFixtures.h
)

target_link_libraries(xdptester
    "Folly::folly"
    "glog::glog"
    pcap_parser
    bpfadapter
)

add_executable(katran_tester katran_tester.cpp)

target_link_libraries(katran_tester
    "${GFLAGS}"
    xdptester
    katranlb
)

enable_testing()

add_executable(base64helpers-tests Base64Test.cpp)
target_link_libraries(base64helpers-tests
    "${GTEST}"
    "glog::glog"
    "${GFLAGS}"
    "Folly::folly"
    "${LIBUNWIND}"
    base64_helpers
    katranlb
)
target_include_directories(
  base64helpers-tests PUBLIC
  "${GTEST_INCLUDE_DIR}"
  ${FOLLY_INCLUDE_DIR}
  base64_helpers
)

add_test(Base64Tests base64helpers-tests)
