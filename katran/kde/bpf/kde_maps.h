#pragma once

#include <katran/kde/bpf/kde_constants.h>
#include "katran/kde/bpf/kde_types.h"

/* Used by the server to detect SYN-ACK retransmissions.
 * BPF_SOCK_OPS_RETRANS_CB is not triggered for SYN-ACK retransmissions.
 * Use an LRU map because requests that never complete do not receive a
 * sockops callback that can remove their entries.
 */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 16384);
  __type(key, struct tuple);
  __type(value, __u8);
} kde_synack_map SEC(".maps");
