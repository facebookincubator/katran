cmake_minimum_required (VERSION 3.9)
project (libkatran_tests)
set(KATRAN_INCLUDE_DIR "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../>")

# find libs
find_library(CHHELPERS chhelpers)
find_path(CHHELPERS_INCLUDE_DIR chhelpers)
find_library(GTEST gtest)
find_path(GTEST_INCLUDE_DIR gtest)
find_package(FOLLY CONFIG REQUIRED)
find_library(PTHREAD pthread)


add_executable(iphelpers-tests IpHelpersTest.cpp)
target_link_libraries(iphelpers-tests
    "${GTEST}"
    "${PTHREAD}"
    "Folly::folly"
    iphelpers
)
target_include_directories(
  iphelpers-tests PUBLIC
  "${GTEST_INCLUDE_DIR}"
  ${FOLLY_INCLUDE_DIR}
  ${KATRAN_INCLUDE_DIR}
)

add_executable(chhelpers-tests CHHelpersTest.cpp)
target_link_libraries(chhelpers-tests
    "${GTEST}"
    "${PTHREAD}"
    katranlb
)
target_include_directories(
  chhelpers-tests PUBLIC
  "${GTEST_INCLUDE_DIR}"
  ${KATRAN_INCLUDE_DIR}
)

add_executable(libkatran-tests KatranLbTest.cpp)
target_link_libraries(libkatran-tests
    "${GTEST}"
    "${PTHREAD}"
    "Folly::folly"
)
target_include_directories(
  libkatran-tests PUBLIC
  "${GTEST_INCLUDE_DIR}"
  "${FOLLY_INCLUDE_DIR}"
)

add_executable(vip-tests VipTest.cpp)
target_link_libraries(vip-tests
    "${GTEST}"
    "${PTHREAD}"
)
target_include_directories(
   vip-tests PUBLIC
  "${GTEST_INCLUDE_DIR}"
)

add_test(IpHelpersTests iphelpers-tests)
add_test(CHHelpersTests chhelpers-tests)
add_test(LibKatranTests libkatran-tests)
add_test(VipTests vip-tests)
