cmake_minimum_required (VERSION 3.0)
project (katranserver-proj)
set (CMAKE_CXX_STANDARD 14)

# thrift cmake macro
find_program(THRIFT1 thrift1)
set(THRIFT_TEMPLATES ${CMAKE_SOURCE_DIR}/deps/fbthrift/thrift/compiler/generate/templates)
include (${CMAKE_SOURCE_DIR}/deps/fbthrift/ThriftLibrary.cmake)
set(THRIFT_PREFIX "katran/if")
set(THRIFT_DIR ${CMAKE_BINARY_DIR}/thrift-out/${THRIFT_PREFIX})
file(MAKE_DIRECTORY ${THRIFT_DIR})

include_directories(${CMAKE_BINARY_DIR}/thrift-out)

thrift_object(
  "katran" #file_name
  "KatranService" #services
  "cpp2" #language
  "" #options
  "${CMAKE_SOURCE_DIR}/example" #file_path
  "${THRIFT_DIR}" #output_path
  "${THRIFT_PREFIX}" #include_prefix
)

find_library(THRIFT thrift)
find_library(THRIFTCPP2 thriftcpp2)
find_library(THRIFTPROTOCOL thriftprotocol)
find_library(CRYPTO crypto)
find_library(EVENT libevent.a event)
find_library(EVENT_CORE libevent_core.a event_core)
find_library(DL dl)
find_library(SSL ssl)
find_library(LIBIBERTY libiberty.a iberty)
find_library(LIBWANGLE libwangle.a wangle)
find_library(LIBTHRIFT_CORE libthrift-core.a thrift-core)
find_library(LIBTHRIFTFROZEN2 libthriftfrozen2.a thriftfrozen2)
find_library(LIBCONCURRENCY libconcurrency.a concurrency)
find_library(LIBTRANSPORT libtransport.a transport)
find_library(LIBASYNC libasync.a async)
find_library(LIBPROTOCOL libprotocol.a protocol)
find_library(LIBGSS gssapi_krb5)
find_library(LIBLZ4 liblz4.so lz4)
find_library(LIBSNAPPY libsnappy.a snappy)
find_library(LIBZSTD libzstd.a zstd)
find_library(LIBBOOST_CONTEXT libboost_context.a boost_context)
find_library(LIBRE2 libre2.a re2)
find_library(LIBSODIUM libsodium.a libsodium)
find_library(LIBFIZZ libfizz.a libfizz)

add_library(simple_service_handler
    KatranSimpleServiceHandler.cpp
    KatranSimpleServiceHandler.h
    $<TARGET_OBJECTS:katran-cpp2-obj>
)
target_link_libraries(simple_service_handler
    katranlb
    "${FOLLY}"
    "${THRIFTCPP2}"
)

add_library(simple_signal_handler
    KatranSimpleServiceSignalHandler.cpp
    KatranSimpleServiceSignalHandler.h
)
target_link_libraries(simple_signal_handler
    "${FOLLY}"
    "${DL}"
    "${EVENT}"

)

add_executable(simple_katran_server KatranSimpleServer.cpp)
target_link_libraries(simple_katran_server
    "-Wl,--start-group"
    "${FOLLY}"
    "${THRIFT}"
    "${THRIFTCPP2}"
    "${THRIFTPROTOCOL}"
    "${LIBTHRIFT_CORE}"
    "${LIBTHRIFTFROZEN2}"
    "${LIBPROTOCOL}"
    "${LIBTRANSPORT}"
    "${LIBCONCURRENCY}"
    "${LIBASYNC}"
    "${LIBWANGLE}"
    "${LIBSODIUM}"
    "${LIBFIZZ}"
    "${LIBGSS}"
    "${LIBLZMA}"
    "${LIBLZ4}"
    "${LIBSNAPPY}"
    "${BOOST_SYSTEM}"
    "${LIBBOOST_CONTEXT}"
    "${DL}"
    "${EVENT_CORE}"
    "${EVENT}"
    "${CRYPTO}"
    "${SSL}"
    "${LIBIBERTY}"
    "${LIBDC}"
    "${GFLAGS}"
    "${GLOG}"
    "${PTHREAD}"
    "${LIBZSTD}"
    mac_helpers
    simple_service_handler
    simple_signal_handler
    "-Wl,--end-group"
)

add_library(katran_client_lib
        client/KatranSimpleClient.cpp
        client/KatranSimpleClient.h
        $<TARGET_OBJECTS:katran-cpp2-obj>
)

target_link_libraries(katran_client_lib
    katranlb
    "-Wl,--start-group"
    "${FOLLY}"
    "${LIBASYNC}"
    "${THRIFT}"
    "${THRIFTCPP2}"
    "${THRIFTPROTOCOL}"
    "${LIBTHRIFT_CORE}"
    "${LIBTHRIFTFROZEN2}"
    "${LIBPROTOCOL}"
    "${LIBTRANSPORT}"
    "${GLOG}"
    "${LIBRE2}"
    "-Wl,--end-group"
)

add_executable(simple_katran_client client/Main.cpp)
target_link_libraries(simple_katran_client
    "-Wl,--start-group"
    "${FOLLY}"
    "${LIBCONCURRENCY}"
    "${LIBASYNC}"
    "${THRIFT}"
    "${THRIFTCPP2}"
    "${THRIFTPROTOCOL}"
    "${LIBTHRIFT_CORE}"
    "${LIBTHRIFTFROZEN2}"
    "${LIBPROTOCOL}"
    "${LIBTRANSPORT}"
    "${LIBWANGLE}"
    "${LIBGSS}"
    "${LIBLZMA}"
    "${LIBLZ4}"
    "${LIBSNAPPY}"
    "${BOOST_SYSTEM}"
    "${LIBBOOST_CONTEXT}"
    "${DL}"
    "${EVENT_CORE}"
    "${EVENT}"
    "${CRYPTO}"
    "${SSL}"
    "${LIBIBERTY}"
    "${LIBDC}"
    "${GFLAGS}"
    "${GLOG}"
    "${PTHREAD}"
    "${LIBZSTD}"
    katran_client_lib
    "-Wl,--end-group"
)
