project (katranserver-proj)

# Defines thrift_generate() and the thrift:: targets of an installed fbthrift.
find_package(FBThrift CONFIG REQUIRED)
pkg_check_modules(RE2 REQUIRED IMPORTED_TARGET re2)

add_library(katran-cpp2-obj OBJECT)
thrift_generate(
  katran-cpp2-obj
  katran.thrift
  LANGUAGE cpp2
  SERVICES KatranService
  OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/thrift-out/katran/if"
  INCLUDE_PREFIX "katran/if"
)
target_include_directories(katran-cpp2-obj PUBLIC "${CMAKE_BINARY_DIR}/thrift-out")
target_link_libraries(katran-cpp2-obj PUBLIC thrift::rpc)

add_library(simple_service_handler
  KatranSimpleServiceHandler.cpp
  KatranSimpleServiceHandler.h
)
target_link_libraries(simple_service_handler PUBLIC katran-cpp2-obj katranlb)

add_library(simple_signal_handler
  KatranSimpleServiceSignalHandler.cpp
  KatranSimpleServiceSignalHandler.h
)
target_link_libraries(simple_signal_handler PUBLIC thrift::rpc)

add_executable(simple_katran_server KatranSimpleServer.cpp)
target_link_libraries(simple_katran_server
  mac_helpers
  simple_service_handler
  simple_signal_handler
)

add_library(katran_client_lib
  client/KatranSimpleClient.cpp
  client/KatranSimpleClient.h
)
target_link_libraries(katran_client_lib PUBLIC katran-cpp2-obj PkgConfig::RE2)

add_executable(simple_katran_client client/Main.cpp)
target_link_libraries(simple_katran_client katran_client_lib)
