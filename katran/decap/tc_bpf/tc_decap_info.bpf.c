/* Copyright (C) 2019-present, Facebook, Inc.
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

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <stdbool.h>
#include <stddef.h>

#include "katran/lib/linux_includes/bpf.h"
#include "katran/lib/linux_includes/bpf_helpers.h"

#include "katran/lib/bpf/balancer_consts.h"
#include "katran/lib/bpf/pckt_encap.h"
#include "katran/lib/bpf/pckt_parsing.h"

#include "pckt_helpers.h"
#include "tc_decap_info_maps.h"
#include "tc_decap_kern_helpers.h"

#define DST_PORT_443 443
#define DST_PORT_8080 8080
#define DST_PORT_7123 7123
#define DST_PORT_7345 7345

__attribute__((__always_inline__)) static inline bool parse_inner_udp(
    void* data,
    void* data_end,
    __u32 inner_offset,
    bool is_inner_ipv6,
    struct flow_key* flow) {
  __u32 off = inner_offset;
  if (is_inner_ipv6) {
    off += sizeof(struct ipv6hdr);
  } else {
    off += sizeof(struct iphdr);
  }
  struct udphdr* udp;
  udp = data + off;

  if (udp + 1 > data_end) {
    return false;
  }

  flow->port16[0] = udp->source;
  flow->port16[1] = udp->dest;
  return true;
}

__attribute__((__always_inline__)) static inline bool parse_inner_tcp(
    void* data,
    void* data_end,
    __u32 inner_offset,
    bool is_inner_ipv6,
    struct flow_key* flow) {
  __u32 off = inner_offset;
  if (is_inner_ipv6) {
    off += sizeof(struct ipv6hdr);
  } else {
    off += sizeof(struct iphdr);
  }
  struct tcphdr* tcp;
  tcp = data + off;

  if (tcp + 1 > data_end) {
    return false;
  }

  flow->port16[0] = tcp->source;
  flow->port16[1] = tcp->dest;

  return true;
}

__attribute__((__always_inline__)) static inline int process_packet(
    void* data,
    __u64 off,
    void* data_end,
    bool is_ipv6,
    struct __sk_buff* skb,
    bool is_inner_ipv6,
    bool is_inner_udp) {
  struct packet_description pckt = {};
  __u32 key = 0;

  int action;
  action = process_l3_headers(data, data_end, off, is_ipv6, &pckt.flow);
  if (action >= 0) {
    return action;
  }
  if (is_ipv6) {
    off =
        sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct udphdr);
  } else {
    off = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
  }

  struct packet_description inner_pckt = {};
  action =
      process_l3_headers(data, data_end, off, is_inner_ipv6, &inner_pckt.flow);
  if (action >= 0) {
    return action;
  }
  if (is_inner_udp) {
    if (!parse_inner_udp(
            data, data_end, off, is_inner_ipv6, &inner_pckt.flow)) {
      return TC_ACT_UNSPEC;
    }
  } else {
    if (!parse_inner_tcp(
            data, data_end, off, is_inner_ipv6, &inner_pckt.flow)) {
      return TC_ACT_UNSPEC;
    }
  }

  if (pckt.flow.proto == IPPROTO_UDP) {
    if (!parse_udp(data, data_end, is_ipv6, &pckt)) {
      return TC_ACT_UNSPEC;
    }
    if ((pckt.flow.port16[1] == bpf_htons(GUE_DPORT)) &&
        ((inner_pckt.flow.port16[1] == bpf_htons(DST_PORT_443)) ||
         (inner_pckt.flow.port16[1] == bpf_htons(DST_PORT_8080)) ||
         (inner_pckt.flow.port16[1] == bpf_htons(DST_PORT_7123)) ||
         (inner_pckt.flow.port16[1] == bpf_htons(DST_PORT_7345)))) {
      int ret = bpf_map_update_elem(
          &pkt_encap_info, &inner_pckt.flow, &pckt.flow, BPF_ANY);
      if (ret) {
        return TC_ACT_UNSPEC;
      }
    }
  }
  return TC_ACT_UNSPEC;
}

__attribute__((__always_inline__)) static inline int
pull_gue_layer(struct __sk_buff* skb, __u32* gue_offset, bool* is_outer_ipv6) {
  void* data = (void*)(long)skb->data;
  void* data_end = (void*)(long)skb->data_end;
  struct ethhdr* eth = data;
  __u32 eth_proto;
  __u32 nh_off;
  __u32 hdr_len;
  nh_off = sizeof(struct ethhdr);

  if (data + nh_off > data_end) {
    // bogus packet, len less than minimum ethernet frame size
    return TC_ACT_SHOT;
  }

  __u32 outer_ip_offset = 0;
  __u8 outer_protocol;
  eth_proto = eth->h_proto;
  if (eth_proto == BE_ETH_P_IP) {
    outer_ip_offset = sizeof(struct iphdr);
  } else if (eth_proto == BE_ETH_P_IPV6) {
    *is_outer_ipv6 = true;
    outer_ip_offset = sizeof(struct ipv6hdr);
  } else {
    // pass to tcp/ip stack
    return TC_ACT_UNSPEC;
  }

  *gue_offset = sizeof(struct ethhdr) + outer_ip_offset + sizeof(struct udphdr);
  int err = bpf_skb_pull_data(skb, (*gue_offset) + 1);
  if (err) {
    // it is not an encapsulated packet
    return TC_ACT_UNSPEC;
  }

  data = (void*)(long)skb->data;
  data_end = (void*)(long)skb->data_end;

  //+1 to read GUEV1_IPV6MASK which is right after gue header
  if (data + hdr_len + 1 > data_end) {
    return TC_ACT_UNSPEC;
  }

  if (eth_proto == BE_ETH_P_IP) {
    struct iphdr* iph = data + nh_off;
    if (iph + 1 > data_end) {
      return TC_ACT_SHOT;
    }
    outer_protocol = iph->protocol;
  } else if (eth_proto == BE_ETH_P_IPV6) {
    struct ipv6hdr* ip6h = data + nh_off;
    if (ip6h + 1 > data_end) {
      return TC_ACT_SHOT;
    }
    outer_protocol = ip6h->nexthdr;
  } else {
    return TC_ACT_UNSPEC;
  }

  if (outer_protocol != IPPROTO_UDP) {
    return TC_ACT_UNSPEC;
  }

  return DECAP_FURTHER_PROCESSING;
}

__attribute__((__always_inline__)) static inline int pull_inner_ip_layer(
    struct __sk_buff* skb,
    bool is_outer_ipv6,
    __u32 gue_offset,
    __u32* inner_ip_offset,
    bool* is_inner_ipv6) {
  void* data = (void*)(long)skb->data;
  void* data_end = (void*)(long)skb->data_end;
  __u32 hdr_len = gue_offset;

  if (data + hdr_len + 1 > data_end) {
    return TC_ACT_UNSPEC;
  }

  struct packet_description pckt = {};
  if (!parse_udp(data, data_end, is_outer_ipv6, &pckt)) {
    return TC_ACT_UNSPEC;
  }
  if (pckt.flow.port16[1] != bpf_htons(GUE_DPORT)) {
    return TC_ACT_UNSPEC;
  }

  __u8 v6 = 0;
  v6 = ((__u8*)(data))[hdr_len];
  v6 &= GUEV1_IPV6MASK;
  if (v6) {
    // inner packet is ipv6 as well
    *is_inner_ipv6 = true;
    *inner_ip_offset = sizeof(struct ipv6hdr);
  } else {
    // inner packet is ipv4
    *inner_ip_offset = sizeof(struct iphdr);
  }

  hdr_len += (*inner_ip_offset);
  int err = bpf_skb_pull_data(skb, hdr_len);
  if (err) {
    return TC_ACT_UNSPEC;
  }

  return DECAP_FURTHER_PROCESSING;
}

__attribute__((__always_inline__)) static inline int pull_inner_tp_layer(
    struct __sk_buff* skb,
    bool is_outer_ipv6,
    __u32 gue_offset,
    __u32 inner_ip_offset,
    bool is_inner_ipv6,
    bool* is_inner_udp) {
  __u8 inner_protocol;
  __u32 hdr_len = gue_offset;
  void* data = (void*)(long)skb->data;
  void* data_end = (void*)(long)skb->data_end;

  if (is_inner_ipv6) {
    if (data + hdr_len + inner_ip_offset > data_end) {
      return TC_ACT_UNSPEC;
    }
    struct ipv6hdr* inner_ip6h = data + hdr_len;
    inner_protocol = inner_ip6h->nexthdr;
  } else {
    if (data + hdr_len + inner_ip_offset > data_end) {
      return TC_ACT_UNSPEC;
    }
    struct iphdr* inner_iph = data + hdr_len;
    inner_protocol = inner_iph->protocol;
  }

  if (inner_protocol == IPPROTO_UDP) {
    *is_inner_udp = true;
  } else if (inner_protocol != IPPROTO_TCP) {
    return TC_ACT_UNSPEC;
  }

  __u32 inner_tp_offset = 0;
  if (is_inner_udp) {
    inner_tp_offset = sizeof(struct udphdr);
  } else {
    inner_tp_offset = sizeof(struct tcphdr);
  }

  int err = bpf_skb_pull_data(skb, hdr_len + inner_ip_offset + inner_tp_offset);
  if (err) {
    return TC_ACT_UNSPEC;
  }

  return DECAP_FURTHER_PROCESSING;
}

SEC("tc") int tcdecapinfo(struct __sk_buff* skb) {
  void* data = (void*)(long)skb->data;
  void* data_end = (void*)(long)skb->data_end;
  struct ethhdr* eth = data;
  __u32 hdr_len;
  __u32 nh_off = sizeof(struct ethhdr);
  bool is_inner_ipv6 = false;
  bool is_inner_udp = false;
  bool is_outer_ipv6 = false;
  __u32 inner_ip_offset = 0;

  int ret = pull_gue_layer(skb, &hdr_len, &is_outer_ipv6);
  if (ret != DECAP_FURTHER_PROCESSING) {
    return ret;
  }

  ret = pull_inner_ip_layer(
      skb, is_outer_ipv6, hdr_len, &inner_ip_offset, &is_inner_ipv6);
  if (ret != DECAP_FURTHER_PROCESSING) {
    return ret;
  }

  ret = pull_inner_tp_layer(
      skb,
      is_outer_ipv6,
      hdr_len,
      inner_ip_offset,
      is_inner_ipv6,
      &is_inner_udp);
  if (ret != DECAP_FURTHER_PROCESSING) {
    return ret;
  }

  data = (void*)(long)skb->data;
  data_end = (void*)(long)skb->data_end;

  return process_packet(
      data, nh_off, data_end, is_outer_ipv6, skb, is_inner_ipv6, is_inner_udp);
}

char _license[] SEC("license") = "GPL";
