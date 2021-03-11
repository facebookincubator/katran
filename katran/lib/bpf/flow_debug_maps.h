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

#ifndef __FLOW_DEBUG_MAPS_H
#define __FLOW_DEBUG_MAPS_H

#include "balancer_structs.h"
#include "bpf.h"
#include "bpf_helpers.h"
#include "flow_debug.h"

struct bpf_map_def SEC("maps") flow_debug_map = {
    .type = BPF_MAP_TYPE_LRU_PERCPU_HASH,
    .key_size = sizeof(struct flow_key),
    .value_size = sizeof(struct flow_debug_info),
    .max_entries = FLOW_DEBUG_MAP_SIZE,
    .map_flags = BPF_F_NO_COMMON_LRU,
};

BPF_ANNOTATE_KV_PAIR(
  flow_debug_map,
  struct flow_key,
  struct flow_debug_info
);



#endif // of __FLOW_DEBUG_MAPS_H
