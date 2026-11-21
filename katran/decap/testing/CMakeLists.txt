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

if(KATRAN_BUILD_BPF)
  katran_add_bpf_test(xdpdecap-tester-ipip
    $<TARGET_FILE:xdpdecap_tester> -test_from_fixtures
    -decap_prog ${KATRAN_BPF_DIR}/decap.bpf.o)
  katran_add_bpf_test(xdpdecap-tester-gue
    $<TARGET_FILE:xdpdecap_tester> -test_from_fixtures -gue
    -decap_prog ${KATRAN_BPF_DIR}/decap.bpf.o)
endif()
