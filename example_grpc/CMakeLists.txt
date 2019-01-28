cmake_minimum_required(VERSION 3.9)
project(katran_grpc)
set (CMAKE_CXX_STANDARD 14)

find_library(PROTOBUF libprotobuf.a protobuf)
set(GRPC_BUILD_PATH "${CMAKE_SOURCE_DIR}/deps/grpc/build/")
set(GRPC_LIBRARIES_PATH "${GRPC_BUILD_PATH}")
set(CARES_LIBRARIES_PATH "${GRPC_LIBRARIES_PATH}/third_party/cares/cares/lib")
find_library(ADDR_SORT libaddress_sorting.a address_sorting PATHS ${GRPC_LIBRARIES_PATH} NO_DEFAULT_PATH)
find_library(GPR libgpr.a gpr PATHS ${GRPC_LIBRARIES_PATH} NO_DEFAULT_PATH)
find_library(GRPC libgrpc.a grpc PATHS ${GRPC_LIBRARIES_PATH} NO_DEFAULT_PATH)
find_library(GRPC++ libgrpc++.a grpc++ PATHS ${GRPC_LIBRARIES_PATH} NO_DEFAULT_PATH)
find_library(CARES libcares.a cares PATHS ${CARES_LIBRARIES_PATH} NO_DEFAULT_PATH)
find_library(GRPC_UNSECURE libgrpc_unsecure.a grpc_unsecure PATHS ${GRPC_LIBRARIES_PATH} NO_DEFAULT_PATH)
find_library(LIBIBERTY libiberty.a iberty)
find_library(DL dl)
find_library(EVENT libevent.a event)
find_package(Protobuf REQUIRED)

set(PROTO_PATH "${CMAKE_SOURCE_DIR}/example_grpc/protos")
set(KATRAN_PROTO "${PROTO_PATH}/katran.proto")
set(GENERATED_PROTOBUF_PATH "${CMAKE_BINARY_DIR}/generated")
file(MAKE_DIRECTORY ${GENERATED_PROTOBUF_PATH})

set(KATRAN_PB_CPP_FILE "${GENERATED_PROTOBUF_PATH}/katran.pb.cc")
set(KATRAN_PB_H_FILE "${GENERATED_PROTOBUF_PATH}/katran.pb.h")
set(KATRAN_GRPC_PB_CPP_FILE "${GENERATED_PROTOBUF_PATH}/katran.grpc.pb.cc")
set(KATRAN_GRPC_PB_H_FILE "${GENERATED_PROTOBUF_PATH}/katran.grpc.pb.h")
message("cmd is ${PROTOBUF_PROTOC_EXECUTABLE}")
add_custom_command(
    OUTPUT "${KATRAN_PB_H_FILE}"
           "${KATRAN_PB_CPP_FILE}"
           "${KATRAN_GRPC_PB_H_FILE}"
           "${KATRAN_GRPC_PB_CPP_FILE}"
    COMMAND ${PROTOBUF_PROTOC_EXECUTABLE}
    ARGS "--proto_path=${PROTO_PATH}"
         "--cpp_out=${GENERATED_PROTOBUF_PATH}"
         "${KATRAN_PROTO}"
    COMMAND ${PROTOBUF_PROTOC_EXECUTABLE}
    ARGS "--proto_path=${PROTO_PATH}"
         "--grpc_out=${GENERATED_PROTOBUF_PATH}"
         "--plugin=protoc-gen-grpc=${GRPC_BUILD_PATH}/grpc_cpp_plugin"
         "${KATRAN_PROTO}"
    COMMENT "generating grpc files"
    )
set(GENERATED_PROTOBUF_FILES ${KATRAN_PB_H_FILE} ${KATRAN_PB_CPP_FILE}
    ${KATRAN_GRPC_PB_H_FILE} ${KATRAN_GRPC_PB_CPP_FILE})

include_directories(${GENERATED_PROTOBUF_PATH})

add_library(katran_service_handler
  "KatranGrpcService.h"
  "KatranGrpcService.cpp"
  ${GENERATED_PROTOBUF_FILES}
)

target_link_libraries(katran_service_handler
  katranlb
  mac_helpers
  "${FOLLY}"
)

add_library(grpc_signal_handler
    GrpcSignalHandler.cpp
    GrpcSignalHandler.h
)

target_link_libraries(grpc_signal_handler
    "${FOLLY}"
    "${DL}"
    "${EVENT}"
    "${GRPC++}"
    "${GPR}"
    "${ADDR_SORT}"
    "${CARES}"
)

add_executable(katran_server_grpc katran_server.cpp)
target_link_libraries(katran_server_grpc
  "-Wl,--start-group"
  "${LIBUNWIND}"
  "${LIBLZMA}"
  "${PROTOBUF}"
  "${GRPC++}"
  "${GPR}"
  "${ADDR_SORT}"
  "${CARES}"
  "${FOLLY}"
  "${GLOG}"
  "${GFLAGS}"
  "${PTHREAD}"
  "${LIBDC}"
  "${DL}"
  "${LIBIBERTY}"
  "${GRPC_UNSECURE}"
  "${LIBZ}"
  katran_service_handler
  grpc_signal_handler
  "-Wl,--end-group"
)
