/* Copyright (C) 2019-present, Facebook, Inc.
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

#ifndef __DECAP_MAPS_H
#define __DECAP_MAPS_H

/*
 * This file contains definition of all maps which has been used by balancer
 */

#include "bpf.h"
#include "bpf_helpers.h"

#ifndef STATS_MAP_SIZE
#define STATS_MAP_SIZE 4
#endif

struct decap_stats {
  __u64 decap_v4;
  __u64 decap_v6;
  __u64 total;
};

// map w/ per vip statistics
struct bpf_map_def SEC("maps") stats = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct decap_stats),
  .max_entries = STATS_MAP_SIZE,
  .map_flags = NO_FLAGS,
};
BPF_ANNOTATE_KV_PAIR(stats, __u32, struct decap_stats);

#endif // of _DECAP_MAPS
