# Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

include(GoogleTest)

# katran_add_test(TARGET <name> [SOURCES <file>...] [DEPENDS <library>...])
#
# Builds a gtest binary around katran's main(), which calls folly::init, and
# registers each of its tests with ctest. SOURCES defaults to <name>.cpp.
function(katran_add_test)
  cmake_parse_arguments(PARSE_ARGV 0 KATRAN_TEST "" "TARGET" "SOURCES;DEPENDS")
  if(NOT KATRAN_TEST_TARGET)
    message(FATAL_ERROR "The TARGET parameter is mandatory.")
  endif()
  if(NOT KATRAN_TEST_SOURCES)
    set(KATRAN_TEST_SOURCES "${KATRAN_TEST_TARGET}.cpp")
  endif()

  add_executable(${KATRAN_TEST_TARGET}
    ${KATRAN_TEST_SOURCES}
    "${KATRAN_FBCODE_ROOT}/katran/lib/tests/common/TestMain.cpp"
  )
  target_link_libraries(${KATRAN_TEST_TARGET} PRIVATE
    ${KATRAN_TEST_DEPENDS}
    ${LIBGMOCK_LIBRARIES}
    Folly::folly
  )
  target_include_directories(${KATRAN_TEST_TARGET} PRIVATE
    ${KATRAN_INCLUDE_DIR}
    ${LIBGMOCK_INCLUDE_DIR}
  )
  target_compile_definitions(${KATRAN_TEST_TARGET} PRIVATE ${LIBGMOCK_DEFINES})

  # PRE_TEST lists the tests when ctest runs, so a binary that cannot start
  # fails its tests rather than the build.
  gtest_discover_tests(${KATRAN_TEST_TARGET}
    DISCOVERY_MODE PRE_TEST
    PROPERTIES TIMEOUT 120
  )
endfunction()
