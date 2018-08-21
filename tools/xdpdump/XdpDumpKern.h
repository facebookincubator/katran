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

#pragma once
#include <string>

const std::string kXdpDumpProg = R"***(

#include <uapi/linux/if_ether.h>
#include <uapi/linux/pkt_cls.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/in.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/icmp.h>
#include <uapi/linux/icmpv6.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>


// we dont want to do htons for each packet, so this is ETH_P_IPV6 and
// ETH_P_IP in be format
#define BE_ETH_P_IP 8
#define BE_ETH_P_IPV6 56710
#define MAX_LEN 128

#define IPV4_HDR_LEN_NO_OPT 20
#define IPV4_PLUS_ICMP_HDR 28
#define IPV6_PLUS_ICMP_HDR 48

// cleint's packet metadata
struct packet_description {
  union {
    __be32 src;
    __be32 srcv6[4];
  };
  union {
    __be32 dst;
    __be32 dstv6[4];
  };
  union {
    __u32 ports;
    __u16 port16[2];
  };
  __u8 proto;
  __u8 flags;
};

struct XdpDumpOutput {
  union {
    __u32 src;
    __u32 srcv6[4];
  };
  union {
    __u32 dst;
    __u32 dstv6[4];
  };
  bool ipv6;
  __u16 sport;
  __u16 dport;
  __u8 proto;
  __u16 pkt_size;
  __u16 data_len;
};


BPF_TABLE("extern", __u32, __u32, jmp, 16);
BPF_PERF_OUTPUT(perf_event_map);

__attribute__((__always_inline__))
static inline __u64 calc_offset(bool is_ipv6) {
  __u64 off = sizeof(struct ethhdr);
  if (is_ipv6) {
    off += sizeof(struct ipv6hdr);
  } else {
    off += sizeof(struct iphdr);
  }
  return off;
}

__attribute__((__always_inline__))
static inline bool parse_udp(void *data, void *data_end,
                             bool is_ipv6,
                             struct packet_description *pckt) {

  __u64 off = calc_offset(is_ipv6);
  struct udphdr *udp;
  udp = data + off;

  if ((void *)(udp + 1) > data_end) {
    return false;
  }

  pckt->port16[0] = udp->source;
  pckt->port16[1] = udp->dest;
  return true;
}


__attribute__((__always_inline__))
static inline bool parse_tcp(void *data, void *data_end,
                             bool is_ipv6,
                             struct packet_description *pckt) {

  __u64 off = calc_offset(is_ipv6);
  struct tcphdr *tcp;
  tcp = data + off;

  if ((void *)(tcp + 1) > data_end) {
    return false;
  }

  pckt->port16[0] = tcp->source;
  pckt->port16[1] = tcp->dest;
  return true;
}

__attribute__((__always_inline__))
static inline void process_packet(void *data, __u64 off, void *data_end,
                                 bool is_ipv6, struct xdp_md *xdp) {
  struct iphdr *iph;
  struct ipv6hdr *ip6h;
  struct packet_description pckt = {};
  __u64 iph_len;
  __u8 protocol;
  struct XdpDumpOutput output = {};

  #ifdef CPU_NUMBER
  if (bpf_get_smp_processor_id() != CPU_NUMBER) {
    return;
  }
  #endif

  if (is_ipv6) {
    ip6h = data + off;
    if ((void *)(ip6h + 1) > data_end) {
      return;
    }

    iph_len = sizeof(struct ipv6hdr);
    protocol = ip6h->nexthdr;
    pckt.proto = protocol;
    off += iph_len;
    memcpy(pckt.srcv6, ip6h->saddr.s6_addr32, 16);
    memcpy(pckt.dstv6, ip6h->daddr.s6_addr32, 16);
  } else {
    iph = data + off;
    if ((void *)(iph + 1) > data_end) {
      return;
    }

    protocol = iph->protocol;
    pckt.proto = protocol;
    off += IPV4_HDR_LEN_NO_OPT;

    pckt.src = iph->saddr;
    pckt.dst = iph->daddr;
  }
  protocol = pckt.proto;

  if (protocol == IPPROTO_TCP) {
    parse_tcp(data, data_end, is_ipv6, &pckt);
  } else if (protocol == IPPROTO_UDP) {
    parse_udp(data, data_end, is_ipv6, &pckt);
  }
  #ifdef SRCV6_0
   if ((pckt.srcv6[0] != SRCV6_0) ||
       (pckt.srcv6[1] != SRCV6_1) ||
       (pckt.srcv6[2] != SRCV6_2) ||
       (pckt.srcv6[3] != SRCV6_3)) {
         return;
       }
  #endif
  #ifdef DSTV6_0
   if ((pckt.dstv6[0] != DSTV6_0) ||
       (pckt.dstv6[1] != DSTV6_1) ||
       (pckt.dstv6[2] != DSTV6_2) ||
       (pckt.dstv6[3] != DSTV6_3)) {
         return;
       }
  #endif
  #ifdef SRCV4
    if(pckt.src != SRCV4) {
      return;
    }
  #endif
  #ifdef DSTV4
    if(pckt.dst != DSTV4) {
      return;
    }
  #endif
  #ifdef SPORT
    if(pckt.port16[0] != SPORT) {
      return;
    }
  #endif
  #ifdef DPORT
    if(pckt.port16[1] != DPORT) {
      return;
    }
  #endif
  #ifdef PROTO
    if(pckt.proto != PROTO) {
      return;
    }
  #endif
  #ifdef OFFSET
    if((data + sizeof(struct ethhdr) + OFFSET + sizeof(__u32)) > data_end) {
      return;
    }
    __u32 pkt_chunk = *(__u32 *)(data + sizeof(struct ethhdr) + OFFSET);
    pkt_chunk &=(0xFFFFFFFF >> ((4 - O_LEN) * 8));
    if ((pkt_chunk & O_PATTERN) != O_PATTERN) {
      return;
    }
  #endif

  output.ipv6 = is_ipv6;
  if (is_ipv6) {
    memcpy(output.srcv6, pckt.srcv6, 16);
    memcpy(output.dstv6, pckt.dstv6, 16);
  } else {
    output.src = pckt.src;
    output.dst = pckt.dst;
  }
  output.sport = pckt.port16[0];
  output.dport = pckt.port16[1];
  output.proto = pckt.proto;
  output.pkt_size = data_end - data;
  __u16 data_len = output.pkt_size < MAX_LEN ? output.pkt_size : MAX_LEN;
  output.data_len = data_len;
  perf_event_map.perf_submit_skb(xdp, data_len, &output, sizeof(output));
  return;
}

__attribute__((__always_inline__))
int xdpdump(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ethhdr *eth = data;
  __u32 eth_proto;
  __u32 nh_off;
  nh_off = sizeof(struct ethhdr);

  if (!(data + nh_off > data_end)) {
    eth_proto = eth->h_proto;

    if (eth_proto == BE_ETH_P_IP) {
      process_packet(data, nh_off, data_end, false, ctx);
    } else if (eth_proto == BE_ETH_P_IPV6) {
      process_packet(data, nh_off, data_end, true, ctx);
    }
  }
  #pragma clang loop unroll(full)
  for (int i = 1; i < 16; i++) {
   jmp.call((void *)ctx, i);
  }
  return XDP_PASS;
}

)***";
