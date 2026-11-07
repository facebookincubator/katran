/* Copyright (C) 2026-present, Meta Platforms, Inc. and affiliates.
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

#ifndef __BALANCER_LOOKUPS_H
#define __BALANCER_LOOKUPS_H

/*
 * This file contains the vip lookup of process_packet, shared with
 * handle_gue_ptb.h, which relays PTBs only for flows to a vip.
 */

#include <stdbool.h>
#include <string.h>

#include "katran/lib/linux_includes/bpf.h"
#include "katran/lib/linux_includes/bpf_helpers.h"

#include "katran/lib/bpf/balancer_consts.h"
#include "katran/lib/bpf/balancer_maps.h"
#include "katran/lib/bpf/balancer_structs.h"

// returns the vip the flow is sent to, filling in vip as it was found, or NULL
// if the flow is for no vip. clears the flow's dst port for a vip of all ports
// which does not hash on it
__attribute__((__always_inline__)) static inline struct vip_meta*
lookup_vip(struct vip_definition* vip, struct flow_key* flow, bool is_ipv6) {
  struct vip_meta* vip_info;
  if (is_ipv6) {
    memcpy(vip->vipv6, flow->dstv6, 16);
  } else {
    vip->vip = flow->dst;
  }

  vip->port = flow->port16[1];
  vip->proto = flow->proto;
  vip_info = bpf_map_lookup_elem(&vip_map, vip);
  if (!vip_info) {
#ifdef CIDR_VIP
    // Try LPM prefix-based VIP lookup with original port+proto (IPv6 only).
    struct vip_lpm_key lpm_key = {};
    if (is_ipv6) {
      lpm_key.prefixlen = 160;
      lpm_key.port = flow->port16[1];
      lpm_key.proto = flow->proto;
      lpm_key.pad = 0;
      memcpy(lpm_key.addr, flow->dstv6, 16);
      vip_info = bpf_map_lookup_elem(&vip_lpm_map, &lpm_key);
    }
#endif // CIDR_VIP
    if (!vip_info) {
      vip->port = 0;
      vip_info = bpf_map_lookup_elem(&vip_map, vip);
      if (!vip_info) {
#ifdef CIDR_VIP
        // Try LPM with port=0 wildcard (IPv6 only).
        if (is_ipv6) {
          lpm_key.port = 0;
          vip_info = bpf_map_lookup_elem(&vip_lpm_map, &lpm_key);
        }
#endif // CIDR_VIP
        if (!vip_info) {
          return NULL;
        }
      }
    }

    if (!(vip_info->flags & F_HASH_DPORT_ONLY) &&
        !(vip_info->flags & F_HASH_SRC_DST_PORT)) {
      // VIP, which doesnt care about dst port (all packets to this VIP w/ diff
      // dst port but from the same src port/ip must go to the same real
      flow->port16[1] = 0;
    }
  }
  return vip_info;
}

#endif // of __BALANCER_LOOKUPS_H
