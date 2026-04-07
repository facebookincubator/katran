/* Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved.
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

#ifndef __HEALTHCHECKING_MAPS_H
#define __HEALTHCHECKING_MAPS_H

#include "katran/lib/linux_includes/bpf.h"
#include "katran/lib/linux_includes/bpf_helpers.h"

#include "katran/lib/bpf/balancer_consts.h"
#include "katran/lib/bpf/healthchecking_consts.h"
#include "katran/lib/bpf/healthchecking_structs.h"

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, CTRL_MAP_SIZE);
} hc_ctrl_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, struct hc_real_definition);
  __uint(max_entries, MAX_REALS);
} hc_reals_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct hc_real_definition);
  __uint(max_entries, 2);
  __uint(map_flags, NO_FLAGS);
} hc_pckt_srcs_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct hc_mac);
  __uint(max_entries, 2);
  __uint(map_flags, NO_FLAGS);
} hc_pckt_macs SEC(".maps");

// map which contains counters for monitoring
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, struct hc_stats);
  __uint(max_entries, STATS_SIZE);
  __uint(map_flags, NO_FLAGS);
} hc_stats_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, MAX_VIPS);
  __uint(map_flags, NO_FLAGS);
} per_hckey_stats SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct hc_key);
  __type(value, __u32);
  __uint(max_entries, MAX_VIPS);
  __uint(map_flags, NO_FLAGS);
} hc_key_map SEC(".maps");

#ifdef HC_DST_MATCH
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct hc_dst_key);
  __type(value, struct hc_real_definition);
  __uint(max_entries, HC_MAX_DST);
  __uint(map_flags, NO_FLAGS);
} hc_dst_reals_map SEC(".maps");
#endif // HC_DST_MATCH

#ifdef HC_SRC_MATCH
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct hc_src_key);
  __type(value, struct hc_real_definition);
  __uint(max_entries, HC_MAX_DST);
  __uint(map_flags, NO_FLAGS);
} hc_src_reals_map SEC(".maps");
#endif // HC_SRC_MATCH

#endif // of __HEALTHCHECKING_MAPS_H
