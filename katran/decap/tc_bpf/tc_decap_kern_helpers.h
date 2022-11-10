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

#ifndef __DECAP_KERN_HELPERS_H
#define __DECAP_KERN_HELPERS_H

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stdbool.h>

#include "katran/lib/linux_includes/bpf.h"
#include "katran/lib/linux_includes/bpf_helpers.h"

__attribute__((__always_inline__)) static inline bool tc_decap_v6(
    struct __sk_buff* skb,
    void** data,
    void** data_end,
    bool inner_v4) {
  __u64 flags = 0;
  int adjust_len;

  struct ethhdr* new_eth;
  struct ethhdr* old_eth;
  old_eth = *data;
  new_eth = *data + sizeof(struct ipv6hdr);
  memcpy(new_eth->h_source, old_eth->h_source, 6);
  memcpy(new_eth->h_dest, old_eth->h_dest, 6);
  if (inner_v4) {
    new_eth->h_proto = BE_ETH_P_IP;
  } else {
    new_eth->h_proto = BE_ETH_P_IPV6;
  }

  flags |= BPF_F_ADJ_ROOM_FIXED_GSO;
  adjust_len = (int)(sizeof(struct ipv6hdr));

  if (bpf_skb_adjust_room(skb, -adjust_len, BPF_ADJ_ROOM_MAC, flags)) {
    return false;
  }

  *data = (void*)(long)skb->data;
  *data_end = (void*)(long)skb->data_end;
  return true;
}

__attribute__((__always_inline__)) static inline bool
tc_decap_v4(struct __sk_buff* skb, void** data, void** data_end) {
  __u64 flags = 0;
  int adjust_len;

  struct ethhdr* new_eth;
  struct ethhdr* old_eth;
  old_eth = *data;
  new_eth = *data + sizeof(struct iphdr);
  memcpy(new_eth->h_source, old_eth->h_source, 6);
  memcpy(new_eth->h_dest, old_eth->h_dest, 6);
  new_eth->h_proto = BE_ETH_P_IP;

  flags |= BPF_F_ADJ_ROOM_FIXED_GSO;
  adjust_len = (int)(sizeof(struct iphdr));

  if (bpf_skb_adjust_room(skb, -adjust_len, BPF_ADJ_ROOM_MAC, flags)) {
    return false;
  }

  *data = (void*)(long)skb->data;
  *data_end = (void*)(long)skb->data_end;
  return true;
}

#ifdef INLINE_DECAP_GUE

__attribute__((__always_inline__)) static inline bool
gue_tc_decap_v4(struct __sk_buff* skb, void** data, void** data_end) {
  __u64 flags = 0;
  int adjust_len;

  struct ethhdr* new_eth;
  struct ethhdr* old_eth;
  old_eth = *data;
  new_eth = *data + sizeof(struct iphdr) + sizeof(struct udphdr);
  RECORD_GUE_ROUTE(old_eth, new_eth, *data_end, true, true);
  memcpy(new_eth->h_source, old_eth->h_source, 6);
  memcpy(new_eth->h_dest, old_eth->h_dest, 6);
  new_eth->h_proto = BE_ETH_P_IP;

  flags |= BPF_F_ADJ_ROOM_FIXED_GSO;
  adjust_len = (int)(sizeof(struct ipv6hdr) + sizeof(struct udphdr));

  if (bpf_skb_adjust_room(skb, -adjust_len, BPF_ADJ_ROOM_MAC, flags)) {
    return false;
  }

  *data = (void*)(long)skb->data;
  *data_end = (void*)(long)skb->data_end;
  return true;
}

__attribute__((__always_inline__)) static inline bool gue_tc_decap_v6(
    struct __sk_buff* skb,
    void** data,
    void** data_end,
    bool inner_v4) {
  __u64 flags = 0;
  int adjust_len;

  struct ethhdr* new_eth;
  struct ethhdr* old_eth;
  old_eth = *data;
  new_eth = *data + sizeof(struct ipv6hdr) + sizeof(struct udphdr);
  RECORD_GUE_ROUTE(old_eth, new_eth, *data_end, false, inner_v4);
  memcpy(new_eth->h_source, old_eth->h_source, 6);
  memcpy(new_eth->h_dest, old_eth->h_dest, 6);
  if (inner_v4) {
    new_eth->h_proto = BE_ETH_P_IP;
  } else {
    new_eth->h_proto = BE_ETH_P_IPV6;
  }

  flags |= BPF_F_ADJ_ROOM_FIXED_GSO;
  adjust_len = (int)(sizeof(struct ipv6hdr) + sizeof(struct udphdr));

  if (bpf_skb_adjust_room(skb, -adjust_len, BPF_ADJ_ROOM_MAC, flags)) {
    return false;
  }

  *data = (void*)(long)skb->data;
  *data_end = (void*)(long)skb->data_end;
  return true;
}
#endif // of INLINE_DECAP_GUE

#endif // of __DECAP_KERN_HELPERS_H
