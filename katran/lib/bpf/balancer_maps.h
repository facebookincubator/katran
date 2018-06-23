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
 * This file contains definition of all maps which has been used by balancer
 */

#include <uapi/linux/bpf.h>

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


// map which contains cpu core to lru mapping
struct bpf_map_def SEC("maps") lru_maps_mapping = {
  .type = BPF_MAP_TYPE_ARRAY_OF_MAPS,
  .key_size = sizeof(u32),
  // index/position of prototype map in inner_maps_fds array
  .inner_map_idx = 0,
  .max_entries = MAX_SUPPORTED_CPUS,
  .map_flags = NO_FLAGS,
};

// fallback lru. we should never hit this one outside of unittests
struct bpf_map_def SEC("maps") fallback_lru_cache = {
  .type = BPF_MAP_TYPE_LRU_HASH,
  .key_size = sizeof(struct flow_key),
  .value_size = sizeof(struct real_pos_lru),
  .max_entries = DEFAULT_LRU_SIZE,
  .map_flags = NO_FLAGS,
};

// map which contains all vip to real mappings
struct bpf_map_def SEC("maps") ch_rings = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(__u32),
  .max_entries = CH_RINGS_SIZE,
  .map_flags = NO_FLAGS,
};

// map which contains opaque real's id to real mapping
struct bpf_map_def SEC("maps") reals = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct real_definition),
  .max_entries = MAX_REALS,
  .map_flags = NO_FLAGS,
};

// map w/ per vip statistics
struct bpf_map_def SEC("maps") stats = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct lb_stats),
  .max_entries = STATS_MAP_SIZE,
  .map_flags = NO_FLAGS,
};

// map for quic connection-id to real's id mapping
struct bpf_map_def SEC("maps") quic_mapping = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(__u32),
  .max_entries = MAX_QUIC_REALS,
  .map_flags = NO_FLAGS,
};

// control array. contains metadata such as default router mac
// and/or interfaces ifindexes
// indexes:
// 0 - default's mac
struct bpf_map_def SEC("maps") ctl_array = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct ctl_value),
  .max_entries = CTL_MAP_SIZE,
  .map_flags = NO_FLAGS,
};

#ifdef LPM_SRC_LOOKUP
struct bpf_map_def SEC("maps") lpm_src_v4 = {
  .type = BPF_MAP_TYPE_LPM_TRIE,
  .key_size = sizeof(struct v4_lpm_key),
  .value_size = sizeof(__u32),
  .max_entries = MAX_LPM_SRC,
  .map_flags = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") lpm_src_v6 = {
  .type = BPF_MAP_TYPE_LPM_TRIE,
  .key_size = sizeof(struct v6_lpm_key),
  .value_size = sizeof(__u32),
  .max_entries = MAX_LPM_SRC,
  .map_flags = BPF_F_NO_PREALLOC,
};
#endif
#ifdef INLINE_DECAP
struct bpf_map_def SEC("maps") decap_dst = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(struct address),
  .value_size = sizeof(__u32),
  .max_entries = MAX_VIPS,
  .map_flags = NO_FLAGS,
};
#endif
#endif // of _BALANCER_MAPS
