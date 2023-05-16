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

#include "katran/lib/linux_includes/bpf.h"
#include "katran/lib/linux_includes/bpf_helpers.h"

#include "katran/lib/bpf/balancer_consts.h"
#include "katran/lib/bpf/balancer_structs.h"

// map, which contains all the vips for which we are doing load balancing
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct vip_definition);
  __type(value, struct vip_meta);
  __uint(max_entries, MAX_VIPS);
  __uint(map_flags, NO_FLAGS);
} vip_map SEC(".maps");

// fallback lru. we should never hit this one outside of unittests
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, struct flow_key);
  __type(value, struct real_pos_lru);
  __uint(max_entries, DEFAULT_LRU_SIZE);
  __uint(map_flags, NO_FLAGS);
} fallback_cache SEC(".maps");

// map which contains cpu core to lru mapping
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, MAX_SUPPORTED_CPUS);
  __uint(map_flags, NO_FLAGS);
  __array(
      values,
      struct {
        __uint(type, BPF_MAP_TYPE_LRU_HASH);
        __type(key, struct flow_key);
        __type(value, struct real_pos_lru);
        __uint(max_entries, DEFAULT_LRU_SIZE);
      });
} lru_mapping SEC(".maps");

// map which contains all vip to real mappings
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, CH_RINGS_SIZE);
  __uint(map_flags, NO_FLAGS);
} ch_rings SEC(".maps");

// map which contains opaque real's id to real mapping
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct real_definition);
  __uint(max_entries, MAX_REALS);
  __uint(map_flags, NO_FLAGS);
} reals SEC(".maps");

// map with per real pps/bps statistic
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, struct lb_stats);
  __uint(max_entries, MAX_REALS);
  __uint(map_flags, NO_FLAGS);
} reals_stats SEC(".maps");

// map with per real lru miss statistic
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32); // key is backend index
  __type(value, __u32); // value is lru miss count of the backend
  __uint(max_entries, MAX_REALS);
  __uint(map_flags, NO_FLAGS);
} lru_miss_stats SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct vip_definition);
  __uint(max_entries, 1);
  __uint(map_flags, NO_FLAGS);
} lru_miss_stats_vip SEC(".maps");

// map w/ per vip statistics
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, struct lb_stats);
  __uint(max_entries, STATS_MAP_SIZE);
  __uint(map_flags, NO_FLAGS);
} stats SEC(".maps");

// map for quic stats
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, struct lb_quic_packets_stats);
  __uint(max_entries, QUIC_STATS_MAP_SIZE);
  __uint(map_flags, NO_FLAGS);
} quic_packets_stats_map SEC(".maps");

// map for server-id to real's id mapping. The ids can be embedded in header of
// QUIC or TCP (if enabled) packets for routing of packets for existing flows
#ifdef SERVER_ID_HASH_MAP
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, MAX_NUM_SERVER_IDS);
  __uint(map_flags, NO_FLAGS);
} server_id_map SEC(".maps");
#else
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, MAX_QUIC_REALS);
  __uint(map_flags, NO_FLAGS);
} server_id_map SEC(".maps");
#endif

#ifdef LPM_SRC_LOOKUP
struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __type(key, struct v4_lpm_key);
  __type(value, __u32);
  __uint(max_entries, MAX_LPM_SRC);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} lpm_src_v4 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __type(key, struct v6_lpm_key);
  __type(value, __u32);
  __uint(max_entries, MAX_LPM_SRC);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} lpm_src_v6 SEC(".maps");

#endif // of LPM_SRC_LOOKUP

#ifdef GLOBAL_LRU_LOOKUP

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, MAX_SUPPORTED_CPUS);
  __uint(map_flags, NO_FLAGS);
  __array(
      values,
      struct {
        __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
        __type(key, struct flow_key);
        __type(value, __u32);
        __uint(max_entries, DEFAULT_LRU_SIZE);
      });
} global_lru_maps SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, struct flow_key);
  __type(value, __u32);
  __uint(max_entries, DEFAULT_GLOBAL_LRU_SIZE);
  __uint(map_flags, NO_FLAGS);
} fallback_glru SEC(".maps");

#endif // of GLOBAL_LRU_LOOKUP

#endif // of _BALANCER_MAPS
