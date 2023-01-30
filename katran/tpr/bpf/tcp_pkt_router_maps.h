// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include "tcp_pkt_router_structs.h"

/* map to store server related info, such as server-id */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(map_flags, NO_FLAGS);
  __uint(max_entries, SERVER_INFO_MAP_SIZE);
  __type(key, __u32); // index of the array
  __type(value, struct server_info);
} server_infos SEC(".maps");

/* BPF sk_storage map to store info for each connection */
struct {
  __uint(type, BPF_MAP_TYPE_SK_STORAGE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, __u32); // socket-fd
  __type(value, __u32); // 4-bytes server_id
} sk_sid_store SEC(".maps");

/* map which contains counters for different packet level events for monitoring
 * purpose */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(map_flags, NO_FLAGS);
  __uint(max_entries, STATS_SIZE);
  __type(key, __u32); // index of the array
  __type(value, struct stats);
} tpr_stats SEC(".maps");
