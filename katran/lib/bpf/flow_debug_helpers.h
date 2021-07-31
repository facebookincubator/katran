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

#ifndef __FLOW_DEBUG_HELPERS_H
#define __FLOW_DEBUG_HELPERS_H

#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "flow_debug_maps.h"

__attribute__((__always_inline__)) static inline __u32
get_next_ports(void* transport_hdr, __u8 proto, void* data_end) {
  __u32 ports = 0;
  struct udphdr *udph = 0;
  struct tcphdr *tcph = 0;

  switch(proto) {
    case IPPROTO_UDP:
      udph = transport_hdr;
      if ((void*)udph + sizeof(struct udphdr) <= data_end) {
        ports = (bpf_ntohs(udph->dest) << 16) | bpf_ntohs(udph->source);
      }
      break;
    case IPPROTO_TCP:
      tcph = transport_hdr;
      if ((void*)tcph + sizeof(struct tcphdr) <= data_end) {
        ports = (bpf_ntohs(tcph->dest) << 16) | bpf_ntohs(tcph->source);
      }
      break;
    default:
      break;
  }

  return ports;
}

__attribute__((__always_inline__)) static inline void
gue_record_route(struct ethhdr* outer_eth, struct ethhdr* inner_eth, void* data_end, bool outer_v4, bool inner_v4) {
  struct flow_key flow = {0};
  struct flow_debug_info debug_info = {0};
  struct ipv6hdr *ip6h = 0;
  struct iphdr *ip4h = 0;
  void *transport_header = 0;

  __u32 cpu_num = bpf_get_smp_processor_id();
  void *flow_debug_map = bpf_map_lookup_elem(&flow_debug_maps, &cpu_num);
  if (!flow_debug_map) {
    return;
  }

  if (outer_v4) {
    if ((void*)outer_eth + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
      return;
    }
    ip4h = (void*)outer_eth + sizeof(struct ethhdr);
    debug_info.l4_hop = ip4h->saddr;
    debug_info.this_hop = ip4h->daddr;
  } else {
    if ((void*)outer_eth + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) > data_end) {
      return;
    }
    ip6h = (void*)outer_eth + sizeof(struct ethhdr);
    __builtin_memcpy(debug_info.l4_hopv6, ip6h->saddr.s6_addr32, sizeof(debug_info.l4_hopv6));
    __builtin_memcpy(debug_info.this_hopv6, ip6h->daddr.s6_addr32, sizeof(debug_info.this_hopv6));
  }

  if (inner_v4) {
    if ((void*)inner_eth + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
      return;
    }
    ip4h = (void*)inner_eth + sizeof(struct ethhdr);
    transport_header = (void*)inner_eth + sizeof(struct ethhdr) + sizeof(struct iphdr);
    flow.src = ip4h->saddr;
    flow.dst = ip4h->daddr;
    flow.proto = ip4h->protocol;
    flow.ports = get_next_ports(transport_header, ip4h->protocol, data_end);
  } else {
    if ((void*)inner_eth + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) > data_end) {
      return;
    }
    ip6h = (void*)inner_eth + sizeof(struct ethhdr);
    transport_header = (void*)inner_eth + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
    __builtin_memcpy(flow.srcv6, ip6h->saddr.s6_addr32, sizeof(flow.srcv6));
    __builtin_memcpy(flow.dstv6, ip6h->daddr.s6_addr32, sizeof(flow.dstv6));
    flow.proto = ip6h->nexthdr;
    flow.ports = get_next_ports(transport_header, ip6h->nexthdr, data_end);
  }
  bpf_map_update_elem(flow_debug_map, &flow, &debug_info, BPF_ANY);
  return;
}

#endif // of __FLOW_DEBUG_HELPERS_H
