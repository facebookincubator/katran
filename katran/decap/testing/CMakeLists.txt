cmake_minimum_required (VERSION 3.0)
project(libdecap_testing)

add_executable(xdpdecap_tester
    xdpdecap_tester.cpp
    XdpDecapTestFixtures.h
)

target_link_libraries(xdpdecap_tester
    "${GFLAGS}"
    "${PTHREAD}"
    xdptester
    decap
)
