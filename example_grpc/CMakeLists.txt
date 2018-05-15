cmake_minimum_required(VERSION 3.9)
project(katran_grpc)

find_library(PROTOBUF libprotobuf.a protobuf)
find_library(GRPC libgrpc.a grpc)
find_library(GRPC++ libgrpc++.a grpc++)
find_library(GRPC_UNSECURE libgrpc_unsecure.a grpc_unsecure)
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
         "--plugin=protoc-gen-grpc=/usr/local/bin/grpc_cpp_plugin"
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
)

add_executable(katran_server_grpc katran_server.cpp)
target_link_libraries(katran_server_grpc
  "-Wl,--start-group"
  "${LIBUNWIND}"
  "${LIBLZMA}"
  "${PROTOBUF}"
  "${GRPC++}"
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
