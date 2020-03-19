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

#ifndef __PCKT_ENCAP_H
#define __PCKT_ENCAP_H

/*
 * This file contains routines which are responsible for encapsulation of the
 * packets, which will be sent out from load balancer. right now we are
 * using IPIP as our encap of choice
 */

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <string.h>

#include "balancer_consts.h"
#include "balancer_helpers.h"
#include "balancer_structs.h"
#include "control_data_maps.h"
#include "bpf.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "encap_helpers.h"
#include "pckt_parsing.h"


__attribute__((__always_inline__)) static inline bool encap_v6(
    struct xdp_md* xdp,
    struct ctl_value* cval,
    bool is_ipv6,
    struct packet_description* pckt,
    struct real_definition* dst,
    __u32 pkt_bytes) {
  void* data;
  void* data_end;
  struct ipv6hdr* ip6h;
  struct eth_hdr* new_eth;
  struct eth_hdr* old_eth;
  __u16 payload_len;
  __u32 ip_suffix;
  __u32 saddr[4];
  __u8 proto;
  // ip(6)ip6 encap
  if (bpf_xdp_adjust_head(xdp, 0 - (int)sizeof(struct ipv6hdr))) {
    return false;
  }
  data = (void*)(long)xdp->data;
  data_end = (void*)(long)xdp->data_end;
  new_eth = data;
  ip6h = data + sizeof(struct eth_hdr);
  old_eth = data + sizeof(struct ipv6hdr);
  if (new_eth + 1 > data_end || old_eth + 1 > data_end || ip6h + 1 > data_end) {
    return false;
  }
  memcpy(new_eth->eth_dest, cval->mac, 6);
  memcpy(new_eth->eth_source, old_eth->eth_dest, 6);
  new_eth->eth_proto = BE_ETH_P_IPV6;

  if (is_ipv6) {
    proto = IPPROTO_IPV6;
    ip_suffix = pckt->flow.srcv6[3] ^ pckt->flow.port16[0];
    payload_len = pkt_bytes + sizeof(struct ipv6hdr);
  } else {
    proto = IPPROTO_IPIP;
    ip_suffix = pckt->flow.src ^ pckt->flow.port16[0];
    payload_len = pkt_bytes;
  }

  saddr[0] = IPIP_V6_PREFIX1;
  saddr[1] = IPIP_V6_PREFIX2;
  saddr[2] = IPIP_V6_PREFIX3;
  saddr[3] = ip_suffix;

  create_v6_hdr(ip6h, pckt->tos, saddr, dst->dstv6, payload_len, proto);

  return true;
}

__attribute__((__always_inline__)) static inline bool encap_v4(
    struct xdp_md* xdp,
    struct ctl_value* cval,
    struct packet_description* pckt,
    struct real_definition* dst,
    __u32 pkt_bytes) {
  void* data;
  void* data_end;
  struct iphdr* iph;
  struct eth_hdr* new_eth;
  struct eth_hdr* old_eth;
  __u32 ip_suffix = bpf_htons(pckt->flow.port16[0]);
  ip_suffix <<= 16;
  ip_suffix ^= pckt->flow.src;
  __u64 csum = 0;
  // ipip encap
  if (bpf_xdp_adjust_head(xdp, 0 - (int)sizeof(struct iphdr))) {
    return false;
  }
  data = (void*)(long)xdp->data;
  data_end = (void*)(long)xdp->data_end;
  new_eth = data;
  iph = data + sizeof(struct eth_hdr);
  old_eth = data + sizeof(struct iphdr);
  if (new_eth + 1 > data_end || old_eth + 1 > data_end || iph + 1 > data_end) {
    return false;
  }
  memcpy(new_eth->eth_dest, cval->mac, 6);
  memcpy(new_eth->eth_source, old_eth->eth_dest, 6);
  new_eth->eth_proto = BE_ETH_P_IP;

  create_v4_hdr(
      iph,
      pckt->tos,
      ((0xFFFF0000 & ip_suffix) | IPIP_V4_PREFIX),
      dst->dst,
      pkt_bytes,
      IPPROTO_IPIP);

  return true;
}

// before calling decap helper apropriate checks for data_end - data must be
// done. otherwise verifier wont like it
__attribute__((__always_inline__)) static inline bool
decap_v6(struct xdp_md* xdp, void** data, void** data_end, bool inner_v4) {
  struct eth_hdr* new_eth;
  struct eth_hdr* old_eth;
  old_eth = *data;
  new_eth = *data + sizeof(struct ipv6hdr);
  memcpy(new_eth->eth_source, old_eth->eth_source, 6);
  memcpy(new_eth->eth_dest, old_eth->eth_dest, 6);
  if (inner_v4) {
    new_eth->eth_proto = BE_ETH_P_IP;
  } else {
    new_eth->eth_proto = BE_ETH_P_IPV6;
  }
  if (bpf_xdp_adjust_head(xdp, (int)sizeof(struct ipv6hdr))) {
    return false;
  }
  *data = (void*)(long)xdp->data;
  *data_end = (void*)(long)xdp->data_end;
  return true;
}

__attribute__((__always_inline__)) static inline bool
decap_v4(struct xdp_md* xdp, void** data, void** data_end) {
  struct eth_hdr* new_eth;
  struct eth_hdr* old_eth;
  old_eth = *data;
  new_eth = *data + sizeof(struct iphdr);
  memcpy(new_eth->eth_source, old_eth->eth_source, 6);
  memcpy(new_eth->eth_dest, old_eth->eth_dest, 6);
  new_eth->eth_proto = BE_ETH_P_IP;
  if (bpf_xdp_adjust_head(xdp, (int)sizeof(struct iphdr))) {
    return false;
  }
  *data = (void*)(long)xdp->data;
  *data_end = (void*)(long)xdp->data_end;
  return true;
}

#ifdef GUE_ENCAP

__attribute__((__always_inline__))
static inline bool gue_encap_v4(struct xdp_md *xdp, struct ctl_value *cval,
                                struct packet_description *pckt,
                                struct real_definition *dst, __u32 pkt_bytes) {
  void *data;
  void *data_end;
  struct iphdr *iph;
  struct udphdr *udph;
  struct eth_hdr *new_eth;
  struct eth_hdr *old_eth;
  struct real_definition *src;

  __u16 sport = bpf_htons(pckt->flow.port16[0]);
  __u32 ipv4_src  = V4_SRC_INDEX;

  src = bpf_map_lookup_elem(&pckt_srcs, &ipv4_src);
  if (!src) {
    return false;
  }
  ipv4_src = src->dst;

  sport ^= ((pckt->flow.src >> 16) & 0xFFFF);
  __u64 csum = 0;

  if (bpf_xdp_adjust_head(
      xdp, 0 - ((int)sizeof(struct iphdr) + (int)sizeof(struct udphdr)))) {
    return false;
  }
  data = (void *)(long)xdp->data;
  data_end = (void *)(long)xdp->data_end;
  new_eth = data;
  iph = data + sizeof(struct eth_hdr);
  udph = (void *)iph + sizeof(struct iphdr);
  old_eth = data + sizeof(struct iphdr) + sizeof(struct udphdr);
  if (new_eth + 1 > data_end ||
      old_eth + 1 > data_end ||
      iph + 1 > data_end ||
      udph + 1 > data_end) {
    return false;
  }
  memcpy(new_eth->eth_dest, cval->mac, sizeof(new_eth->eth_dest));
  memcpy(new_eth->eth_source, old_eth->eth_dest, sizeof(new_eth->eth_source));
  new_eth->eth_proto = BE_ETH_P_IP;

  create_udp_hdr(
    udph,
    sport,
    GUE_DPORT,
    pkt_bytes + sizeof(struct udphdr),
    GUE_CSUM);

  create_v4_hdr(
    iph,
    pckt->tos,
    ipv4_src,
    dst->dst,
    pkt_bytes + sizeof(struct udphdr),
    IPPROTO_UDP);

  return true;
}

__attribute__((__always_inline__))
static inline bool gue_encap_v6(struct xdp_md *xdp, struct ctl_value *cval,
                                bool is_ipv6, struct packet_description *pckt,
                                struct real_definition *dst, __u32 pkt_bytes) {
  void *data;
  void *data_end;
  struct ipv6hdr *ip6h;
  struct eth_hdr *new_eth;
  struct eth_hdr *old_eth;
  struct udphdr *udph;
  __u32 key = V6_SRC_INDEX;
  __u16 payload_len;
  __u16 sport;
  struct real_definition *src;

  src = bpf_map_lookup_elem(&pckt_srcs, &key);
  if (!src) {
    return false;
  }

  if (bpf_xdp_adjust_head(
    xdp, 0 - ((int)sizeof(struct ipv6hdr) + (int)sizeof(struct udphdr)))) {
    return false;
  }
  data = (void *)(long)xdp->data;
  data_end = (void *)(long)xdp->data_end;
  new_eth = data;
  ip6h = data + sizeof(struct eth_hdr);
  udph = (void *)ip6h + sizeof(struct ipv6hdr);
  old_eth = data + sizeof(struct ipv6hdr) + sizeof(struct udphdr);
  if (new_eth + 1 > data_end ||
      old_eth + 1 > data_end ||
      ip6h + 1 > data_end ||
      udph + 1 > data_end) {
    return false;
  }
  memcpy(new_eth->eth_dest, cval->mac, 6);
  memcpy(new_eth->eth_source, old_eth->eth_dest, 6);
  new_eth->eth_proto = BE_ETH_P_IPV6;


  if (is_ipv6) {
    sport = (pckt->flow.srcv6[3] & 0xFFFF) ^ pckt->flow.port16[0];
    pkt_bytes += (sizeof(struct ipv6hdr) + sizeof(struct udphdr));
  } else {
    sport = ((pckt->flow.src >> 16) & 0xFFFF) ^ pckt->flow.port16[0];
    pkt_bytes += sizeof(struct udphdr);
  }

  create_udp_hdr(
    udph,
    sport,
    GUE_DPORT,
    pkt_bytes,
    GUE_CSUM);

  create_v6_hdr(ip6h, pckt->tos, src->dstv6, dst->dstv6, pkt_bytes, IPPROTO_UDP);

  return true;
}
#endif // of GUE_ENCAP


#ifdef INLINE_DECAP_GUE

__attribute__((__always_inline__)) static inline bool
gue_decap_v4(struct xdp_md* xdp, void** data, void** data_end) {
  struct eth_hdr* new_eth;
  struct eth_hdr* old_eth;
  old_eth = *data;
  new_eth = *data + sizeof(struct iphdr) + sizeof(struct udphdr);
  memcpy(new_eth->eth_source, old_eth->eth_source, 6);
  memcpy(new_eth->eth_dest, old_eth->eth_dest, 6);
  new_eth->eth_proto = BE_ETH_P_IP;
  if (bpf_xdp_adjust_head(
          xdp, (int)(sizeof(struct iphdr) + sizeof(struct udphdr)))) {
    return false;
  }
  *data = (void*)(long)xdp->data;
  *data_end = (void*)(long)xdp->data_end;
  return true;
}

__attribute__((__always_inline__)) static inline bool
gue_decap_v6(struct xdp_md* xdp, void** data, void** data_end, bool inner_v4) {
  struct eth_hdr* new_eth;
  struct eth_hdr* old_eth;
  old_eth = *data;
  new_eth = *data + sizeof(struct ipv6hdr) + sizeof(struct udphdr);
  memcpy(new_eth->eth_source, old_eth->eth_source, 6);
  memcpy(new_eth->eth_dest, old_eth->eth_dest, 6);
  if (inner_v4) {
    new_eth->eth_proto = BE_ETH_P_IP;
  } else {
    new_eth->eth_proto = BE_ETH_P_IPV6;
  }
  if (bpf_xdp_adjust_head(
          xdp, (int)(sizeof(struct ipv6hdr) + sizeof(struct udphdr)))) {
    return false;
  }
  *data = (void*)(long)xdp->data;
  *data_end = (void*)(long)xdp->data_end;
  return true;
}
#endif // of INLINE_DECAP_GUE



#endif // of __PCKT_ENCAP_H
