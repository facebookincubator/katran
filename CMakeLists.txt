cmake_minimum_required (VERSION 3.9)

project(
  katran
)

set(CMAKE_MODULE_PATH
  "${CMAKE_CURRENT_SOURCE_DIR}/build/fbcode_builder/CMake"
  ${CMAKE_MODULE_PATH})

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# KATRAN_FBCODE_ROOT is where the top level katran/ directory resides, so
# an #include <katran/path/to/file> will resolve to
# $KATRAN_FBCODE_ROOT/katran/path/to/file on disk
set(KATRAN_FBCODE_ROOT ${CMAKE_CURRENT_SOURCE_DIR})

set(KATRAN_INCLUDE_DIR "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../>")

# for clang's compile_commands.json
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_COMPILER_ID "Clang")

set(CMAKE_CXX_STANDARD 14)

# Dependencies
find_package(folly CONFIG REQUIRED)
find_package(Fizz REQUIRED)
find_package(Glog REQUIRED)
find_package(Gflags REQUIRED)
find_package(Threads)

SET(LIBFIZZ_LIBRARY ${FIZZ_LIBRARIES})
SET(LIBFIZZ_INCLUDE_DIR ${FIZZ_INCLUDE_DIR})

include_directories(".")
add_subdirectory(katran)

if(BUILD_TESTS)
  enable_testing()
endif()

if(DEFINED ENV{CMAKE_BUILD_EXAMPLE_THRIFT})
    message("Building example of thrift and grpc based katran server")
    add_subdirectory(example)
endif()

if(DEFINED ENV{CMAKE_BUILD_EXAMPLE_GRPC})
    add_subdirectory(example_grpc)
endif()
message("Building tools/utils for katran")

install(
  EXPORT katran-exports
  FILE katran-targets.cmake
  NAMESPACE katran::
  DESTINATION lib/cmake/katran/
)

include(CMakePackageConfigHelpers)
configure_package_config_file(
  cmake/katran-config.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/katran-config.cmake
  INSTALL_DESTINATION lib/cmake/katran/
)

install(
  FILES ${CMAKE_CURRENT_BINARY_DIR}/katran-config.cmake
  DESTINATION lib/cmake/katran/
)
