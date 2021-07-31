/* Copyright (C) 2018-present, Facebook, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __BALANCER_MAPS_H
#define __BALANCER_MAPS_H

/*
 * This file contains definition of maps used by the balancer typically
 * involving information pertaining to proper forwarding of packets
 */

#include "bpf.h"
#include "bpf_helpers.h"

#include "balancer_consts.h"
#include "balancer_structs.h"

// map, which contains all the vips for which we are doing load balancing
struct bpf_map_def SEC("maps") vip_map = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(struct vip_definition),
  .value_size = sizeof(struct vip_meta),
  .max_entries = MAX_VIPS,
  .map_flags = NO_FLAGS,
};
BPF_ANNOTATE_KV_PAIR(vip_map, struct vip_definition, struct vip_meta);


// map which contains cpu core to lru mapping
struct bpf_map_def SEC("maps") lru_mapping = {
  .type = BPF_MAP_TYPE_ARRAY_OF_MAPS,
  .key_size = sizeof(__u32),
  .value_size = sizeof(__u32),
  .max_entries = MAX_SUPPORTED_CPUS,
  .map_flags = NO_FLAGS,
};

// fallback lru. we should never hit this one outside of unittests
struct bpf_map_def SEC("maps") fallback_cache = {
  .type = BPF_MAP_TYPE_LRU_HASH,
  .key_size = sizeof(struct flow_key),
  .value_size = sizeof(struct real_pos_lru),
  .max_entries = DEFAULT_LRU_SIZE,
  .map_flags = NO_FLAGS,
};
BPF_ANNOTATE_KV_PAIR(fallback_cache, struct flow_key, struct real_pos_lru);

// map which contains all vip to real mappings
struct bpf_map_def SEC("maps") ch_rings = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(__u32),
  .max_entries = CH_RINGS_SIZE,
  .map_flags = NO_FLAGS,
};
BPF_ANNOTATE_KV_PAIR(ch_rings, __u32, __u32);

// map which contains opaque real's id to real mapping
struct bpf_map_def SEC("maps") reals = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct real_definition),
  .max_entries = MAX_REALS,
  .map_flags = NO_FLAGS,
};
BPF_ANNOTATE_KV_PAIR(reals, __u32, struct real_definition);

// map with per real pps/bps statistic
struct bpf_map_def SEC("maps") reals_stats = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct lb_stats),
  .max_entries = MAX_REALS,
  .map_flags = NO_FLAGS,
};
BPF_ANNOTATE_KV_PAIR(reals_stats, __u32, struct lb_stats);

// map w/ per vip statistics
struct bpf_map_def SEC("maps") stats = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct lb_stats),
  .max_entries = STATS_MAP_SIZE,
  .map_flags = NO_FLAGS,
};
BPF_ANNOTATE_KV_PAIR(stats, __u32, struct lb_stats);

// map for server-id to real's id mapping. The ids can be embedded in header of
// QUIC or TCP (if enabled) packets for routing of packets for existing flows
struct bpf_map_def SEC("maps") server_id_map = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(__u32),
  .max_entries = MAX_QUIC_REALS,
  .map_flags = NO_FLAGS,
};
BPF_ANNOTATE_KV_PAIR(server_id_map, __u32, __u32);

#ifdef LPM_SRC_LOOKUP
struct bpf_map_def SEC("maps") lpm_src_v4 = {
  .type = BPF_MAP_TYPE_LPM_TRIE,
  .key_size = sizeof(struct v4_lpm_key),
  .value_size = sizeof(__u32),
  .max_entries = MAX_LPM_SRC,
  .map_flags = BPF_F_NO_PREALLOC,
};
BPF_ANNOTATE_KV_PAIR(lpm_src_v4, struct v4_lpm_key, __u32);

struct bpf_map_def SEC("maps") lpm_src_v6 = {
  .type = BPF_MAP_TYPE_LPM_TRIE,
  .key_size = sizeof(struct v6_lpm_key),
  .value_size = sizeof(__u32),
  .max_entries = MAX_LPM_SRC,
  .map_flags = BPF_F_NO_PREALLOC,
};
BPF_ANNOTATE_KV_PAIR(lpm_src_v6, struct v6_lpm_key, __u32);

#endif

#endif // of _BALANCER_MAPS
