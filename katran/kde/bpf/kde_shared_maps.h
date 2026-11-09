#pragma once

#include "katran/kde/bpf/kde_types.h"

// Map shared between SockOps and TC prog, used to pass DirectEncap IP
// associated with established socket from SockOps to TC.
struct {
  __uint(type, BPF_MAP_TYPE_SK_STORAGE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, __u32); // socket-fd
  __type(value, struct encap_sk_info);
} katran_de_sk_store SEC(".maps");

/* used when sk_store is not available
   ex: when KDE TC runs on host egress, and forwarded skb->sk is nulled out
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 131072);
  __type(key, struct tuple);
  __type(value, struct encap_sk_info);
} katran_de_tuple_store SEC(".maps");
