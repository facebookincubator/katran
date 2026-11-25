cmake_minimum_required(VERSION 3.22...3.24)

project(katran LANGUAGES C CXX)

list(PREPEND CMAKE_MODULE_PATH
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake"
  "${CMAKE_CURRENT_SOURCE_DIR}/tool/fbcode_builder/CMake"
)

# KATRAN_FBCODE_ROOT holds katran/, so #include <katran/...> resolves under it.
set(KATRAN_FBCODE_ROOT ${CMAKE_CURRENT_SOURCE_DIR})
set(KATRAN_INCLUDE_DIR
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
  "$<INSTALL_INTERFACE:include>"
)

# Before folly: a folly built here only picks C++20 if nothing is set.
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(BUILD_TESTS "Build katran's tests" OFF)
option(KATRAN_BUILD_BPF "Build katran's BPF programs, which needs clang" ON)
option(KATRAN_BUILD_TPR "Build the TCP packet router, which needs bpftool" OFF)
option(KATRAN_BUILD_KDE "Build Katran DirectEncap, which needs bpftool, fb303, fbthrift, and opentelemetry-cpp" OFF)
option(KATRAN_BUILD_EXAMPLE_THRIFT
  "Build the thrift example server, which needs an installed fbthrift" OFF)
option(KATRAN_BUILD_EXAMPLE_GRPC
  "Build the gRPC example server, which needs an installed gRPC" OFF)
option(KATRAN_BUILD_TOOLS "Build tools/" OFF)

# folly, and for the tests googletest and CLI11, are fetched and built at the
# revisions getdeps pins when they aren't installed. Everything else has to be
# installed.
include(FBFetchFromManifest)

# A dependency built here is missing from an install of katran, so katran's
# install rules are turned off, unless CMAKE_SKIP_INSTALL_RULES is set.
set(katran_build_local_deps "")
macro(katran_build_local name)
  list(APPEND katran_build_local_deps ${name})
  if(NOT DEFINED CMAKE_SKIP_INSTALL_RULES)
    set(CMAKE_SKIP_INSTALL_RULES ON)
  endif()
endmacro()

find_package(folly CONFIG QUIET)
if(NOT folly_FOUND)
  katran_build_local(folly)
  fb_fetch_from_manifest(folly folly)
endif()
# folly finds or fetches glog. gflags it only fetches for its own tests, and
# katran defines flags, so gflags has to be installed.
find_package(Glog REQUIRED)
find_package(Gflags REQUIRED)
find_package(Threads REQUIRED)
find_package(ZLIB REQUIRED)
find_package(PkgConfig REQUIRED)
# getdeps builds libbpf as a static library, which needs libelf, zlib and zstd
# linked after it.
pkg_check_modules(BPF REQUIRED libbpf)
pkg_check_modules(LIBELF REQUIRED libelf)
pkg_check_modules(LIBMNL REQUIRED libmnl)
pkg_check_modules(ZSTD REQUIRED libzstd)

if(BUILD_TESTS OR KATRAN_BUILD_KDE)
  # fb_find_or_fetch() would look for a manifest named cli11.
  find_package(CLI11 CONFIG QUIET)
  if(NOT CLI11_FOUND)
    fb_fetch_from_manifest(CLI11 CLI11)
  endif()
endif()

if(BUILD_TESTS)
  enable_testing()
  fb_find_or_fetch_gmock()
  include(KatranTest)
endif()

if(KATRAN_BUILD_BPF)
  include(KatranBpf)
endif()

if(katran_build_local_deps)
  list(JOIN katran_build_local_deps ", " text)
  message(STATUS "Install rules are off because this build makes its own "
                 "${text}. Install it and reconfigure for an installable katran.")
endif()

include_directories(".")
add_subdirectory(katran)

if(KATRAN_BUILD_EXAMPLE_THRIFT)
  add_subdirectory(example)
endif()

if(KATRAN_BUILD_EXAMPLE_GRPC)
  add_subdirectory(example_grpc)
endif()

if(KATRAN_BUILD_TOOLS)
  add_subdirectory(tools)
endif()

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
