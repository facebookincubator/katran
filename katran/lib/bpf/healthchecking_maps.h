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

#include "bpf.h"
#include "bpf_helpers.h"

#include "balancer_consts.h"
#include "healthchecking_consts.h"
#include "healthchecking_structs.h"

struct bpf_map_def SEC("maps") hc_ctrl_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = CTRL_MAP_SIZE,
};
BPF_ANNOTATE_KV_PAIR(hc_ctrl_map, __u32, __u32);

struct bpf_map_def SEC("maps") hc_reals_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct hc_real_definition),
    .max_entries = MAX_REALS,
};
BPF_ANNOTATE_KV_PAIR(hc_reals_map, __u32, struct hc_real_definition);

struct bpf_map_def SEC("maps") hc_pckt_srcs_map = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct hc_real_definition),
  .max_entries = 2,
  .map_flags = NO_FLAGS,
};
BPF_ANNOTATE_KV_PAIR(hc_pckt_srcs_map, __u32, struct hc_real_definition);

struct bpf_map_def SEC("maps") hc_pckt_macs = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct hc_mac),
  .max_entries = 2,
  .map_flags = NO_FLAGS,
};
BPF_ANNOTATE_KV_PAIR(hc_pckt_macs, __u32, struct hc_mac);

// map which contains counters for monitoring
struct bpf_map_def SEC("maps") hc_stats_map = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct hc_stats),
    .max_entries = STATS_SIZE,
    .map_flags = NO_FLAGS,
};
BPF_ANNOTATE_KV_PAIR(hc_stats_map, __u32, struct hc_stats);



#endif // of __HEALTHCHECKING_MAPS_H
