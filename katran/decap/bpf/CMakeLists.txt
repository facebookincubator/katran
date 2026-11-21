katran_bpf_object(bpf_decap
  SOURCE decap.bpf.c OUTPUT decap.bpf.o
  DEFINES -DGUE_DPORT=9886 -DINLINE_DECAP_GUE -DDECAP_TPR_STATS)
