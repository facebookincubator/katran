add_executable(xdpdecap_tester
    xdpdecap_tester.cpp
    XdpDecapGueTestFixtures.h
    XdpDecapTestFixtures.h
)

target_link_libraries(xdpdecap_tester
    ${LIBGFLAGS_LIBRARY}
    Threads::Threads
    bpftester
    decap
)
