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

#include "tc_decap_kern_helpers.h"
#include "tc_decap_maps.h"

__attribute__((__always_inline__)) static inline int process_l3_headers(
    struct packet_description* pckt,
    __u8* protocol,
    __u64 off,
    __u16* pkt_bytes,
    void* data,
    void* data_end,
    bool is_ipv6) {
  __u64 iph_len;
  struct iphdr* iph;
  struct ipv6hdr* ip6h;

  if (is_ipv6) {
    ip6h = data + off;
    if (ip6h + 1 > data_end) {
      return TC_ACT_SHOT;
    }

    iph_len = sizeof(struct ipv6hdr);
    *protocol = ip6h->nexthdr;
    pckt->flow.proto = *protocol;
    *pkt_bytes = bpf_ntohs(ip6h->payload_len);
    off += iph_len;
    if (*protocol == IPPROTO_FRAGMENT) {
      // we drop fragmented packets
      return TC_ACT_SHOT;
    }
  } else {
    iph = data + off;
    if (iph + 1 > data_end) {
      return TC_ACT_SHOT;
    }
    // ihl contains len of ipv4 header in 32bit words
    if (iph->ihl != 5) {
      // if len of ipv4 hdr is not equal to 20bytes that means that header
      // contains ip options, and we dont support em
      return TC_ACT_SHOT;
    }

    *protocol = iph->protocol;
    pckt->flow.proto = *protocol;
    *pkt_bytes = bpf_ntohs(iph->tot_len);
    off += IPV4_HDR_LEN_NO_OPT;

    if (iph->frag_off & PCKT_FRAGMENTED) {
      // we drop fragmented packets.
      return TC_ACT_SHOT;
    }
  }
  return FURTHER_PROCESSING;
}

__attribute__((__always_inline__)) static inline int process_encaped_gue_pckt(
    void** data,
    void** data_end,
    struct __sk_buff* skb,
    bool is_ipv6) {
  int offset = 0;
  if (is_ipv6) {
    __u8 v6 = 0;
    offset =
        sizeof(struct ipv6hdr) + sizeof(struct ethhdr) + sizeof(struct udphdr);
    // 1 byte for gue v1 marker to figure out what is internal protocol
    if ((*data + offset + 1) > *data_end) {
      return TC_ACT_SHOT;
    }
    v6 = ((__u8*)(*data))[offset];
    v6 &= GUEV1_IPV6MASK;
    if (v6) {
      // inner packet is ipv6 as well
      if (!gue_tc_decap_v6(skb, data, data_end, false)) {
        return TC_ACT_SHOT;
      }
    } else {
      // inner packet is ipv4
      if (!gue_tc_decap_v6(skb, data, data_end, true)) {
        return TC_ACT_SHOT;
      }
    }
  } else {
    offset =
        sizeof(struct iphdr) + sizeof(struct ethhdr) + sizeof(struct udphdr);
    if ((*data + offset) > *data_end) {
      return TC_ACT_SHOT;
    }
    if (!gue_tc_decap_v4(skb, data, data_end)) {
      return TC_ACT_SHOT;
    }
  }
  return FURTHER_PROCESSING;
}

__attribute__((__always_inline__)) static inline int process_packet(
    void* data,
    __u64 off,
    void* data_end,
    bool is_ipv6,
    struct __sk_buff* skb) {
  struct packet_description pckt = {};
  struct decap_stats* data_stats;
  __u32 key = 0;
  __u8 protocol;

  int action;
  __u16 pkt_bytes;
  action = process_l3_headers(
      &pckt, &protocol, off, &pkt_bytes, data, data_end, is_ipv6);
  if (action >= 0) {
    return action;
  }
  protocol = pckt.flow.proto;

  data_stats = bpf_map_lookup_elem(&decap_counters, &key);
  if (!data_stats) {
    return TC_ACT_UNSPEC;
  }

  data_stats->total += 1;
  if (protocol == IPPROTO_UDP) {
    if (!parse_udp(data, data_end, is_ipv6, &pckt)) {
      return TC_ACT_UNSPEC;
    }
    if (pckt.flow.port16[1] == bpf_htons(GUE_DPORT)) {
      if (is_ipv6) {
        data_stats->decap_v6 += 1;
      } else {
        data_stats->decap_v4 += 1;
      }
      action = process_encaped_gue_pckt(&data, &data_end, skb, is_ipv6);
      if (action >= 0) {
        return action;
      }
    }
  }
  return TC_ACT_UNSPEC;
}

SEC("tc")
int tcdecap(struct __sk_buff* skb) {
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

  eth_proto = eth->h_proto;

  if (eth_proto == BE_ETH_P_IP) {
    struct iphdr* iph = data + nh_off;
    hdr_len = sizeof(struct ethhdr) + sizeof(struct iphdr) +
        sizeof(struct udphdr) + 1;
    if (data + hdr_len > data_end) {
      int err = bpf_skb_pull_data(skb, hdr_len);
      if (err) {
        // it is not an encapsulated packet
        return TC_ACT_UNSPEC;
      }
      data = (void*)(long)skb->data;
      data_end = (void*)(long)skb->data_end;
    }
    return process_packet(data, nh_off, data_end, false, skb);
  } else if (eth_proto == BE_ETH_P_IPV6) {
    struct ipv6hdr* ip6h = data + nh_off;
    // we need extra 1 byte because first four byte of the udp payload encodes
    // gue variant
    hdr_len = sizeof(struct ethhdr) + sizeof(struct ipv6hdr) +
        sizeof(struct udphdr) + 1;
    if (data + hdr_len > data_end) {
      int err = bpf_skb_pull_data(skb, hdr_len);
      if (err) {
        // it is not an encapsulated packet
        return TC_ACT_UNSPEC;
      }
      data = (void*)(long)skb->data;
      data_end = (void*)(long)skb->data_end;
    }
    return process_packet(data, nh_off, data_end, true, skb);
  } else {
    // pass to tcp/ip stack
    return TC_ACT_UNSPEC;
  }
}

char _license[] SEC("license") = "GPL";
