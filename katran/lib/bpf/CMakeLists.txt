# The flags Makefile-bpf gave every program here.
set(defines -DDEBUG -D__KERNEL__ -Wno-unused-value -Wno-pointer-sign)

katran_bpf_object(bpf_balancer
  SOURCE balancer.bpf.c OUTPUT balancer.bpf.o DEFINES ${defines})
katran_bpf_object(bpf_healthchecking
  SOURCE healthchecking.bpf.c OUTPUT healthchecking.bpf.o DEFINES ${defines})
katran_bpf_object(bpf_healthchecking_ipip
  SOURCE healthchecking_ipip.c OUTPUT healthchecking_ipip.o DEFINES ${defines})
katran_bpf_object(bpf_xdp_pktcntr
  SOURCE xdp_pktcntr.c OUTPUT xdp_pktcntr.o DEFINES ${defines})
katran_bpf_object(bpf_xdp_root
  SOURCE xdp_root.c OUTPUT xdp_root.o DEFINES ${defines})

# katran_tester's fixtures, with IPIP and with GUE encapsulation.
set(test_defines ${defines} -DKATRAN_TEST_MODE)
katran_bpf_object(bpf_balancer_test
  SOURCE balancer.bpf.c OUTPUT balancer_test.bpf.o DEFINES ${test_defines})
katran_bpf_object(bpf_balancer_test_gue
  SOURCE balancer.bpf.c OUTPUT balancer_test_gue.bpf.o
  DEFINES ${test_defines} -DGUE_ENCAP -DGUE_DPORT=9886)
