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

#ifndef __HEALTHCHECKING_HELPERS_H
#define __HEALTHCHECKING_HELPERS_H

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/string.h>
#include <linux/udp.h>
#include <stdbool.h>

#include "bpf.h"
#include "bpf_helpers.h"

#include "encap_helpers.h"

#include "healthchecking_structs.h"
#include "healthchecking_maps.h"


__attribute__((__always_inline__)) static inline bool hc_encap_ipip(
  struct __sk_buff *skb,
  struct hc_real_definition *real,
  struct ethhdr* ethh,
  bool is_ipv6
) {
  struct hc_real_definition *src;
  __u64 flags = 0;
  __u16 pkt_len;
  int adjust_len;
  __u32 key;

  pkt_len = skb->len - sizeof(struct ethhdr);

  if (real->flags == V6DADDR) {
    __u8 proto = IPPROTO_IPV6;
    key = V6_SRC_INDEX;
    src = bpf_map_lookup_elem(&hc_pckt_srcs_map, &key);
    if (!src) {
      return false;
    }
    flags |= BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_ENCAP_L3_IPV6;
    adjust_len = sizeof(struct ipv6hdr);
    // new header would be inserted after MAC but before old L3 header
    if(bpf_skb_adjust_room(skb, adjust_len, BPF_ADJ_ROOM_MAC, flags)) {
      return false;
    }
    if ((skb->data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr)) > skb->data_end) {
      return false;
    }
    ethh = (void*)(long)skb->data;
    ethh->h_proto = BE_ETH_P_IPV6;

    struct ipv6hdr *ip6h = (void*)(long)skb->data + sizeof(struct ethhdr);
    if (!is_ipv6) {
      proto = IPPROTO_IPIP;
    }
    create_v6_hdr(ip6h, DEFAULT_TOS, src->v6daddr, real->v6daddr, pkt_len, proto);
  } else {
    __u8 proto = IPPROTO_IPIP;
    key = V4_SRC_INDEX;
    src = bpf_map_lookup_elem(&hc_pckt_srcs_map, &key);
    if (!src) {
      return false;
    }
    flags |= BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_ENCAP_L3_IPV4;
    adjust_len = sizeof(struct iphdr);
    // new header would be inserted after MAC but before old L3 header
    if(bpf_skb_adjust_room(skb, adjust_len, BPF_ADJ_ROOM_MAC, flags)) {
      return false;
    }
    if ((skb->data + sizeof(struct ethhdr) + sizeof(struct iphdr)) > skb->data_end) {
      return false;
    }
    ethh = (void*)(long)skb->data;
    ethh->h_proto = BE_ETH_P_IP;

    struct iphdr *iph = (void*)(long)skb->data + sizeof(struct ethhdr);
    if (is_ipv6) {
      proto = IPPROTO_IPV6;
    }
    create_v4_hdr(iph, DEFAULT_TOS, src->daddr, real->daddr, pkt_len, proto);
  }
  return true;
}

__attribute__((__always_inline__)) static inline __u16 gue_sport(__u32 seed) {
  return (__u16)((seed ^ (seed >> 16)) & 0xFFFF);
}

__attribute__((__always_inline__)) static inline bool hc_encap_gue(
  struct __sk_buff *skb,
  struct hc_real_definition *real,
  struct ethhdr* ethh,
  bool is_ipv6
) {
  struct hc_real_definition *src;
  __u64 flags = 0;
  __u16 pkt_len;
  __u16 sport;
  int adjust_len;
  __u32 key;

  pkt_len = skb->len - sizeof(struct ethhdr);

  if (real->flags == V6DADDR) {
    sport = gue_sport(real->v6daddr[0] | real->v6daddr[3]);
    __u8 proto = IPPROTO_IPV6;
    key = V6_SRC_INDEX;
    src = bpf_map_lookup_elem(&hc_pckt_srcs_map, &key);
    if (!src) {
      return false;
    }
    flags |= BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_ENCAP_L3_IPV6 | BPF_F_ADJ_ROOM_ENCAP_L4_UDP;
    adjust_len = sizeof(struct ipv6hdr) + sizeof(struct udphdr);
    // new headers would be inserted after MAC but before old L3 header
    if(bpf_skb_adjust_room(skb, adjust_len, BPF_ADJ_ROOM_MAC, flags)) {
      return false;
    }
    if ((skb->data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) +
        sizeof(struct udphdr)) > skb->data_end) {
      return false;
    }
    ethh = (void*)(long)skb->data;
    ethh->h_proto = BE_ETH_P_IPV6;

    struct ipv6hdr *ip6h = (void*)(long)skb->data + sizeof(struct ethhdr);
    struct udphdr *udph = (void*)ip6h + sizeof(struct ipv6hdr);
    pkt_len += sizeof(struct udphdr);
    create_udp_hdr(udph, sport, GUE_DPORT, pkt_len, GUE_CSUM);
    create_v6_hdr(ip6h, DEFAULT_TOS, src->v6daddr, real->v6daddr, pkt_len, IPPROTO_UDP);
  } else {
    sport = gue_sport(real->daddr);
    key = V4_SRC_INDEX;
    src = bpf_map_lookup_elem(&hc_pckt_srcs_map, &key);
    if (!src) {
      return false;
    }
    flags |= BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 | BPF_F_ADJ_ROOM_ENCAP_L4_UDP;
    adjust_len = sizeof(struct iphdr) + sizeof(struct udphdr);
    // new headers would be inserted after MAC but before old L3 header
    if(bpf_skb_adjust_room(skb, adjust_len, BPF_ADJ_ROOM_MAC, flags)) {
      return false;
    }
    if ((skb->data + sizeof(struct ethhdr) + sizeof(struct iphdr) +
        sizeof(struct udphdr)) > skb->data_end) {
      return false;
    }
    ethh = (void*)(long)skb->data;
    ethh->h_proto = BE_ETH_P_IP;

    struct iphdr *iph = (void*)(long)skb->data + sizeof(struct ethhdr);
    struct udphdr *udph = (void*)iph + sizeof(struct iphdr);
    pkt_len += sizeof(struct udphdr);
    create_udp_hdr(udph, sport, GUE_DPORT, pkt_len, GUE_CSUM);
    create_v4_hdr(iph, DEFAULT_TOS, src->daddr, real->daddr, pkt_len, IPPROTO_UDP);
  }
  return true;
}


#endif // of __HEALTHCHECKING_HELPERS_H
