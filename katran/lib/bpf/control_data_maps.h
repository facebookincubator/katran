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
struct bpf_map_def SEC("maps") ctl_array = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct ctl_value),
  .max_entries = CTL_MAP_SIZE,
  .map_flags = NO_FLAGS,
};
BPF_ANNOTATE_KV_PAIR(ctl_array, __u32, struct ctl_value);

#ifdef KATRAN_INTROSPECTION

struct bpf_map_def SEC("maps") event_pipe = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(__u32),
    .max_entries = MAX_SUPPORTED_CPUS,
    .map_flags = NO_FLAGS,
};
BPF_ANNOTATE_KV_PAIR(event_pipe, int, __u32);

#endif

#ifdef INLINE_DECAP_GENERIC
struct bpf_map_def SEC("maps") decap_dst = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct address),
    .value_size = sizeof(__u32),
    .max_entries = MAX_VIPS,
    .map_flags = NO_FLAGS,
};
BPF_ANNOTATE_KV_PAIR(decap_dst, struct address, __u32);

struct bpf_map_def SEC("maps") katran_subprograms = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = SUBPROGRAMS_ARRAY_SIZE,
};
BPF_ANNOTATE_KV_PAIR(katran_subprograms, __u32, __u32);
#endif

#ifdef GUE_ENCAP
// map which src ip address for outer ip packet while using GUE encap
// NOTE: This is not a stable API. This is to be reworked when static
// variables will be available in mainline kernels
struct bpf_map_def SEC("maps") pckt_srcs = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct real_definition),
    .max_entries = 2,
    .map_flags = NO_FLAGS,
};
BPF_ANNOTATE_KV_PAIR(pckt_srcs, __u32, struct real_definition);
#endif

#endif // of __CONTROL_DATA_MAPS_H
