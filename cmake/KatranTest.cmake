
include(CTest)
if(BUILD_TESTS)
  find_library(BOOST_SYSTEM libboost_system.a boost_system)
  find_package(FOLLY CONFIG REQUIRED)
  find_library(GTEST gtest)
  find_path(GTEST_INCLUDE_DIR gtest)
  find_library(PTHREAD pthread)
  include(GoogleTest)
endif()

function(katran_add_test)
  if(NOT BUILD_TESTS)
    return()
  endif()

  set(options)
  set(one_value_args TARGET WORKING_DIRECTORY PREFIX)
  set(multi_value_args SOURCES DEPENDS INCLUDES EXTRA_ARGS)
  cmake_parse_arguments(PARSE_ARGV 0 KATRAN_TEST "${options}" "${one_value_args}" "${multi_value_args}")

  if(NOT KATRAN_TEST_TARGET)
    message(FATAL_ERROR "The TARGET parameter is mandatory.")
  endif()

  if(NOT KATRAN_TEST_SOURCES)
    set(KATRAN_TEST_SOURCES "${KATRAN_TEST_TARGET}.cpp")
  endif()

  add_executable(${KATRAN_TEST_TARGET}
    "${KATRAN_TEST_SOURCES}"
    # implementation of 'main()' that also calls folly::init
    "${KATRAN_FBCODE_ROOT}/katran/lib/tests/common/TestMain.cpp"
  )

  target_link_libraries(${KATRAN_TEST_TARGET} PRIVATE
    "${KATRAN_TEST_DEPENDS}"
     ${GTEST}
  )

  target_include_directories(${KATRAN_TEST_TARGET} PRIVATE
    ${BPF_INCLUDE_DIRS}
    ${GTEST_INCLUDE_DIR}
    ${FOLLY_INCLUDE_DIR}
    ${KATRAN_INCLUDE_DIR}
    ${KATRAN_EXTRA_INCLUDE_DIRECTORIES}
    ${KATRAN_TEST_INCLUDES}
  )

  gtest_discover_tests("${KATRAN_TEST_TARGET}"
    EXTRA_ARGS "${KATRAN_TEST_EXTRA_ARGS}"
    WORKING_DIRECTORY "${KATRAN_TEST_WORKING_DIRECTORY}"
    TEST_PREFIX ${KATRAN_TEST_PREFIX}
  TEST_LIST KATRAN_TEST_CASES)

  set_tests_properties(${KATRAN_TEST_CASES} PROPERTIES TIMEOUT 120)
endfunction()
