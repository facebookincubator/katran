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
#include "flow_debug.h"
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
  struct ethhdr* new_eth;
  struct ethhdr* old_eth;
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
  ip6h = data + sizeof(struct ethhdr);
  old_eth = data + sizeof(struct ipv6hdr);
  if (new_eth + 1 > data_end || old_eth + 1 > data_end || ip6h + 1 > data_end) {
    return false;
  }
  memcpy(new_eth->h_dest, cval->mac, 6);
  memcpy(new_eth->h_source, old_eth->h_dest, 6);
  new_eth->h_proto = BE_ETH_P_IPV6;

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
  struct ethhdr* new_eth;
  struct ethhdr* old_eth;
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
  iph = data + sizeof(struct ethhdr);
  old_eth = data + sizeof(struct iphdr);
  if (new_eth + 1 > data_end || old_eth + 1 > data_end || iph + 1 > data_end) {
    return false;
  }
  memcpy(new_eth->h_dest, cval->mac, 6);
  memcpy(new_eth->h_source, old_eth->h_dest, 6);
  new_eth->h_proto = BE_ETH_P_IP;

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
  if (bpf_xdp_adjust_head(xdp, (int)sizeof(struct ipv6hdr))) {
    return false;
  }
  *data = (void*)(long)xdp->data;
  *data_end = (void*)(long)xdp->data_end;
  return true;
}

__attribute__((__always_inline__)) static inline bool
decap_v4(struct xdp_md* xdp, void** data, void** data_end) {
  struct ethhdr* new_eth;
  struct ethhdr* old_eth;
  old_eth = *data;
  new_eth = *data + sizeof(struct iphdr);
  memcpy(new_eth->h_source, old_eth->h_source, 6);
  memcpy(new_eth->h_dest, old_eth->h_dest, 6);
  new_eth->h_proto = BE_ETH_P_IP;
  if (bpf_xdp_adjust_head(xdp, (int)sizeof(struct iphdr))) {
    return false;
  }
  *data = (void*)(long)xdp->data;
  *data_end = (void*)(long)xdp->data_end;
  return true;
}

#ifdef GUE_ENCAP

__attribute__((__always_inline__)) static inline bool gue_csum(
    void* data,
    void* data_end,
    bool outer_v6,
    bool inner_v6,
    struct packet_description* pckt,
    __u64* csum) {
  // offsets for different header types
  __u16 outer_ip_off;
  __u16 udp_hdr_off;
  __u16 inner_ip_off;
  __u16 inner_transport_off;
  struct udphdr* udph;

  outer_ip_off = sizeof(struct ethhdr);
  udp_hdr_off = outer_v6 ? outer_ip_off + sizeof(struct ipv6hdr)
                         : outer_ip_off + sizeof(struct iphdr);
  inner_ip_off = udp_hdr_off + sizeof(struct udphdr);
  inner_transport_off = inner_v6 ? inner_ip_off + sizeof(struct ipv6hdr)
                                 : inner_ip_off + sizeof(struct iphdr);
  if (data + inner_transport_off > data_end) {
    return false;
  }

  if (pckt->flow.proto == IPPROTO_UDP) {
    struct udphdr* inner_udp = data + inner_transport_off;
    if (inner_udp + 1 > data_end) {
      return false;
    }
    *csum = inner_udp->check;
  } else if (pckt->flow.proto == IPPROTO_TCP) {
    struct tcphdr* inner_tcp = data + inner_transport_off;
    if (inner_tcp + 1 > data_end) {
      return false;
    }
    *csum = inner_tcp->check;
  } else {
    return false;
  }

  if (inner_v6) {
    // encapsulation for ipv6 in ipv4 is not supported
    struct ipv6hdr* outer_ip6h = data + outer_ip_off;
    udph = (void*)data + udp_hdr_off;
    struct ipv6hdr* inner_ip6h = data + inner_ip_off;
    if (outer_ip6h + 1 > data_end || udph + 1 > data_end ||
        inner_ip6h + 1 > data_end) {
      return false;
    }
    return gue_csum_v6(outer_ip6h, udph, inner_ip6h, csum);
  } else {
    if (outer_v6) {
      struct ipv6hdr* outer_ip6h = data + outer_ip_off;
      udph = data + udp_hdr_off;
      struct iphdr* inner_iph = data + inner_ip_off;
      if (outer_ip6h + 1 > data_end || udph + 1 > data_end ||
          inner_iph + 1 > data_end) {
        return false;
      }
      return gue_csum_v4_in_v6(outer_ip6h, udph, inner_iph, csum);
    } else {
      struct iphdr* outer_iph = data + outer_ip_off;
      udph = data + udp_hdr_off;
      struct iphdr* inner_iph = data + inner_ip_off;
      if (outer_iph + 1 > data_end || udph + 1 > data_end ||
          inner_iph + 1 > data_end) {
        return false;
      }
      return gue_csum_v4(outer_iph, udph, inner_iph, csum);
    }
  }
  return true;
}

__attribute__((__always_inline__))
static inline bool gue_encap_v4(struct xdp_md *xdp, struct ctl_value *cval,
                                struct packet_description *pckt,
                                struct real_definition *dst, __u32 pkt_bytes) {
  void *data;
  void *data_end;
  struct iphdr *iph;
  struct udphdr *udph;
  struct ethhdr *new_eth;
  struct ethhdr *old_eth;
  struct real_definition *src;

  __u16 sport = bpf_htons(pckt->flow.port16[0]);
  __u32 ipv4_src  = V4_SRC_INDEX;

  src = bpf_map_lookup_elem(&pckt_srcs, &ipv4_src);
  if (!src) {
    return false;
  }
  ipv4_src = src->dst;

  sport ^= ((pckt->flow.src >> 16) & 0xFFFF);

  if (bpf_xdp_adjust_head(
      xdp, 0 - ((int)sizeof(struct iphdr) + (int)sizeof(struct udphdr)))) {
    return false;
  }
  data = (void *)(long)xdp->data;
  data_end = (void *)(long)xdp->data_end;
  new_eth = data;
  iph = data + sizeof(struct ethhdr);
  udph = (void *)iph + sizeof(struct iphdr);
  old_eth = data + sizeof(struct iphdr) + sizeof(struct udphdr);
  if (new_eth + 1 > data_end || old_eth + 1 > data_end || iph + 1 > data_end ||
      udph + 1 > data_end) {
    return false;
  }
  memcpy(new_eth->h_dest, cval->mac, sizeof(new_eth->h_dest));
  memcpy(new_eth->h_source, old_eth->h_dest, sizeof(new_eth->h_source));
  new_eth->h_proto = BE_ETH_P_IP;

  create_udp_hdr(udph, sport, GUE_DPORT, pkt_bytes + sizeof(struct udphdr), 0);
  create_v4_hdr(
      iph,
      pckt->tos,
      ipv4_src,
      dst->dst,
      pkt_bytes + sizeof(struct udphdr),
      IPPROTO_UDP);
  __u64 csum = 0;
  if (gue_csum(data, data_end, false, false, pckt, &csum)) {
    udph->check = csum & 0xFFFF;
  }
  return true;
}

__attribute__((__always_inline__))
static inline bool gue_encap_v6(struct xdp_md *xdp, struct ctl_value *cval,
                                bool is_ipv6, struct packet_description *pckt,
                                struct real_definition *dst, __u32 pkt_bytes) {
  void *data;
  void *data_end;
  struct ipv6hdr *ip6h;
  struct ethhdr *new_eth;
  struct ethhdr *old_eth;
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
  ip6h = data + sizeof(struct ethhdr);
  udph = (void *)ip6h + sizeof(struct ipv6hdr);
  old_eth = data + sizeof(struct ipv6hdr) + sizeof(struct udphdr);
  if (new_eth + 1 > data_end ||
      old_eth + 1 > data_end ||
      ip6h + 1 > data_end ||
      udph + 1 > data_end) {
    return false;
  }
  memcpy(new_eth->h_dest, cval->mac, 6);
  memcpy(new_eth->h_source, old_eth->h_dest, 6);
  new_eth->h_proto = BE_ETH_P_IPV6;

  if (is_ipv6) {
    sport = (pckt->flow.srcv6[3] & 0xFFFF) ^ pckt->flow.port16[0];
    pkt_bytes += (sizeof(struct ipv6hdr) + sizeof(struct udphdr));
  } else {
    sport = ((pckt->flow.src >> 16) & 0xFFFF) ^ pckt->flow.port16[0];
    pkt_bytes += sizeof(struct udphdr);
  }

  create_udp_hdr(udph, sport, GUE_DPORT, pkt_bytes, 0);
  create_v6_hdr(
      ip6h, pckt->tos, src->dstv6, dst->dstv6, pkt_bytes, IPPROTO_UDP);
  __u64 csum = 0;
  if (gue_csum(data, data_end, true, is_ipv6, pckt, &csum)) {
    udph->check = csum & 0xFFFF;
  }
  return true;
}
#endif // of GUE_ENCAP

#ifdef INLINE_DECAP_GUE

__attribute__((__always_inline__)) static inline bool
gue_decap_v4(struct xdp_md* xdp, void** data, void** data_end) {
  struct ethhdr* new_eth;
  struct ethhdr* old_eth;
  old_eth = *data;
  new_eth = *data + sizeof(struct iphdr) + sizeof(struct udphdr);
  RECORD_GUE_ROUTE(old_eth, new_eth, *data_end, true, true);
  memcpy(new_eth->h_source, old_eth->h_source, 6);
  memcpy(new_eth->h_dest, old_eth->h_dest, 6);
  new_eth->h_proto = BE_ETH_P_IP;
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
