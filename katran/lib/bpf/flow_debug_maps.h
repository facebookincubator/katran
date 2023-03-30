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

#include "katran/lib/linux_includes/bpf.h"
#include "katran/lib/linux_includes/bpf_helpers.h"

#include "katran/lib/bpf/balancer_structs.h"
#include "katran/lib/bpf/flow_debug.h"

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
        __uint(key_size, sizeof(struct flow_key));
        __uint(value_size, sizeof(struct flow_debug_info));
        __uint(max_entries, DEFAULT_LRU_SIZE);
      });
} flow_debug_maps SEC(".maps");

#endif // of __FLOW_DEBUG_MAPS_H
