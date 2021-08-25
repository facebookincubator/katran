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

#ifndef __CONTROL_DATA_MAPS_H
#define __CONTROL_DATA_MAPS_H

/*
 * This file contains definition of maps used for passing of control data and
 * information about encapsulation / decapsulation
 */

#include "bpf.h"
#include "bpf_helpers.h"

#include "balancer_consts.h"
#include "balancer_structs.h"

// control array. contains metadata such as default router mac
// and/or interfaces ifindexes
// indexes:
// 0 - default's mac
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct ctl_value);
  __uint(max_entries, CTL_MAP_SIZE);
  __uint(map_flags, NO_FLAGS);
} ctl_array SEC(".maps");

#ifdef KATRAN_INTROSPECTION

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __type(key, int);
  __type(value, __u32);
  __uint(max_entries, MAX_SUPPORTED_CPUS);
  __uint(map_flags, NO_FLAGS);
} event_pipe SEC(".maps");

#endif

#ifdef INLINE_DECAP_GENERIC
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct address);
  __type(value, __u32);
  __uint(max_entries, MAX_VIPS);
  __uint(map_flags, NO_FLAGS);
} decap_dst SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, SUBPROGRAMS_ARRAY_SIZE);
} subprograms SEC(".maps");
#endif

#ifdef GUE_ENCAP
// map which src ip address for outer ip packet while using GUE encap
// NOTE: This is not a stable API. This is to be reworked when static
// variables will be available in mainline kernels
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct real_definition);
  __uint(max_entries, 2);
  __uint(map_flags, NO_FLAGS);

} pckt_srcs SEC(".maps");
#endif

#endif // of __CONTROL_DATA_MAPS_H
