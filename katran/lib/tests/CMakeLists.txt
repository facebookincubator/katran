cmake_minimum_required (VERSION 3.0)
enable_testing()
project (libkatran_tests)

add_executable(iphelpers-tests IpHelpersTest.cpp)
target_link_libraries(iphelpers-tests
    "${GTEST}"
    "${PTHREAD}"
    iphelpers
)

add_executable(chhelpers-tests CHHelpersTest.cpp)
target_link_libraries(chhelpers-tests
    "${GTEST}"
    "${PTHREAD}"
    chhelpers
)

add_executable(libkatran-tests KatranLbTest.cpp)
target_link_libraries(libkatran-tests
    "${GTEST}"
    "${PTHREAD}"
    katranlb
)

add_executable(vip-tests VipTest.cpp)
target_link_libraries(vip-tests
    "${GTEST}"
    "${PTHREAD}"
    katranlb
)
add_test(IpHelpersTests iphelpers-tests)
add_test(CHHelpersTests chhelpers-tests)
add_test(LibKatranTests libkatran-tests)
add_test(VipTests vip-tests)
