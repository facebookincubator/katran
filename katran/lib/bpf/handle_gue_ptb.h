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

#ifndef __HANDLE_GUE_PTB_H
#define __HANDLE_GUE_PTB_H

/*
 * This file contains routines which relay ICMP "packet too big" messages sent
 * by a hop between katran and a real for a GUE encapsulated packet: the hop
 * reports the mtu to katran, which sourced the outer packet, and katran tells
 * the client on behalf of the vip. Only built with GUE_PTB_RELAY.
 *
 * A PTB is relayed only if it quotes enough of the client's packet to quote
 * GUE_PTB_QUOTE_V6/V4 bytes of it back. IPv4 hops that quote just the 8 bytes
 * past the ip header RFC 792 requires, rather than the larger quote RFC 1812
 * asks for, are counted as truncated and never relayed.
 *
 * Anything which is not relayed takes the regular path, as it did before the
 * relay existed, and only moves the relay's counters.
 *
 * The relay trusts any PTB sent to katran's GUE source which quotes a GUE
 * packet sourced by katran and a flow to a vip. katran's GUE source is a host
 * address which the firewall keeps unreachable from outside the network, so
 * only a host inside it can spoof one. The relay does not check that katran
 * sent the quoted flow to the quoted real: lrus are per cpu, so the PTB rarely
 * sees the flow's, and flows routed by quic connection id, tcp server id, udp
 * stable routing or src routing do not follow the ch ring, so such a check
 * drops legitimate PTBs and leaves their flows black holed.
 *
 * Relayed PTBs are not rate limited. The relay sends at most one PTB per PTB it
 * receives, and a smaller one, so it cannot amplify; hops police their own
 * ICMP generation; and a spoofed PTB can only lower one client's mtu for a
 * vip, never below GUE_PTB_RELAY_MIN_MTU_V6/V4. A rate limit would mostly drop
 * the legitimate PTBs of a hop's mtu change: they all come from one hop to one
 * address, so they land on one cpu. This matches ICMP_TOOBIG_GENERATION, which
 * answers every oversized packet, and Linux, which exempts PTBs from its ICMP
 * rate limits because limiting them breaks PMTUD, though RFC 4443 asks nodes to
 * limit the ICMPv6 errors they originate.
 */

#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <stdbool.h>

#include "katran/lib/linux_includes/bpf.h"
#include "katran/lib/linux_includes/bpf_endian.h"
#include "katran/lib/linux_includes/bpf_helpers.h"

#include "katran/lib/bpf/balancer_consts.h"
#include "katran/lib/bpf/balancer_helpers.h"
#include "katran/lib/bpf/balancer_lookups.h"
#include "katran/lib/bpf/balancer_maps.h"
#include "katran/lib/bpf/balancer_structs.h"
#include "katran/lib/bpf/control_data_maps.h"
#include "katran/lib/bpf/handle_icmp.h"

// how much of the client's packet the relayed PTB quotes, which the hop's PTB
// must therefore carry: the same as for the PTBs katran generates itself, so
// that the relay reuses send_icmp_too_big and its fixed size checksums. both
// cover the client's ip and transport headers, which is all a client needs to
// match the PTB to its socket
#define GUE_PTB_QUOTE_V6 (ICMP6_TOOBIG_SIZE - sizeof(struct ethhdr))
#define GUE_PTB_QUOTE_V4 (ICMP_TOOBIG_SIZE - sizeof(struct ethhdr))

// headers in front of the quoted client's packet: ip and icmp of the PTB, then
// the quoted outer ip and udp headers katran encapsulated the packet with.
// the PTB's own ip header has no options or extension headers, as
// parse_l3_headers drops IPv4 with ihl != 5 and only reaches the ICMPv6 path
// for nexthdr == IPPROTO_ICMPV6. parse_gue_ptb_v4 checks the same for the
// quoted outer header, and katran's encap never adds any
#define GUE_PTB_HDRS_V6                                                        \
  (sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr) + sizeof(struct ipv6hdr) + \
   sizeof(struct udphdr))
#define GUE_PTB_HDRS_V4                                                   \
  (sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + \
   sizeof(struct udphdr))

// PTB quoting a GUE packet katran sent
struct gue_ptb {
  // the client's flow as katran saw it: src is the client, dst the vip
  struct flow_key flow;
  // mtu the hop reported
  __u32 mtu;
  // length of the client's packet
  __u32 pckt_len;
  bool inner_ipv6;
  // the PTB quotes too little of the client's packet to relay it
  bool truncated;
};

__attribute__((__always_inline__)) static inline void incr_gue_ptb_relay_stats(
    __u32 offset,
    bool is_ipv6) {
  __u32 stats_key = MAX_VIPS + offset;
  struct lb_stats* data_stats = bpf_map_lookup_elem(&stats, &stats_key);
  if (!data_stats) {
    return;
  }
  if (is_ipv6) {
    data_stats->v2 += 1;
  } else {
    data_stats->v1 += 1;
  }
}

__attribute__((__always_inline__)) static inline bool parse_gue_ptb_inner(
    void* inner,
    void* data_end,
    bool outer_ipv6,
    struct gue_ptb* ptb) {
  __u8* gue_hdr = inner;
  if (gue_hdr + 1 > data_end) {
    ptb->truncated = true;
    return true;
  }
  ptb->inner_ipv6 = *gue_hdr & GUEV1_IPV6MASK;
  if (ptb->inner_ipv6) {
    if (!outer_ipv6) {
      // katran does not encapsulate v6 packets in v4
      return false;
    }
    if (inner + GUE_PTB_QUOTE_V6 > data_end) {
      ptb->truncated = true;
      return true;
    }
    struct ipv6hdr* ip6h = inner;
    __u16* ports = inner + sizeof(struct ipv6hdr);
    ptb->flow.proto = ip6h->nexthdr;
    memcpy(ptb->flow.srcv6, ip6h->saddr.s6_addr32, 16);
    memcpy(ptb->flow.dstv6, ip6h->daddr.s6_addr32, 16);
    ptb->flow.port16[0] = ports[0];
    ptb->flow.port16[1] = ports[1];
    ptb->pckt_len = bpf_ntohs(ip6h->payload_len) + sizeof(struct ipv6hdr);
  } else {
    if (inner + GUE_PTB_QUOTE_V4 > data_end) {
      ptb->truncated = true;
      return true;
    }
    struct iphdr* iph = inner;
    __u16* ports = inner + sizeof(struct iphdr);
    if (iph->version != 4 || iph->ihl != 5) {
      return false;
    }
    ptb->flow.proto = iph->protocol;
    ptb->flow.src = iph->saddr;
    ptb->flow.dst = iph->daddr;
    ptb->flow.port16[0] = ports[0];
    ptb->flow.port16[1] = ports[1];
    ptb->pckt_len = bpf_ntohs(iph->tot_len);
  }
  return ptb->flow.proto == IPPROTO_TCP || ptb->flow.proto == IPPROTO_UDP;
}

__attribute__((__always_inline__)) static inline bool gue_ptb_is_src_v6(
    struct in6_addr* addr,
    struct real_definition* src) {
  return src->dstv6[0] == addr->s6_addr32[0] &&
      src->dstv6[1] == addr->s6_addr32[1] &&
      src->dstv6[2] == addr->s6_addr32[2] &&
      src->dstv6[3] == addr->s6_addr32[3];
}

// returns true if the packet at off is an ICMPv6 PTB quoting a GUE packet
// sourced by katran. a hop sends its PTB to the source of the packet it could
// not forward, so a PTB sent to any other address is not for the relay
__attribute__((__always_inline__)) static inline bool
parse_gue_ptb_v6(void* data, void* data_end, __u64 off, struct gue_ptb* ptb) {
  struct ipv6hdr* outer = data + sizeof(struct ethhdr);
  struct icmp6hdr* icmp_hdr = data + off;
  struct ipv6hdr* ip6h = (void*)(icmp_hdr + 1);
  struct udphdr* udp = (void*)(ip6h + 1);
  if (outer + 1 > data_end || udp + 1 > data_end) {
    return false;
  }
  if (icmp_hdr->icmp6_type != ICMPV6_PKT_TOOBIG ||
      ip6h->nexthdr != IPPROTO_UDP || udp->dest != bpf_htons(GUE_DPORT)) {
    return false;
  }
  __u32 key = V6_SRC_INDEX;
  struct real_definition* src = bpf_map_lookup_elem(&pckt_srcs, &key);
  if (!src || !gue_ptb_is_src_v6(&outer->daddr, src) ||
      !gue_ptb_is_src_v6(&ip6h->saddr, src)) {
    return false;
  }
  ptb->mtu = bpf_ntohl(icmp_hdr->icmp6_mtu);
  return parse_gue_ptb_inner(udp + 1, data_end, true, ptb);
}

// returns true if the packet at off is an ICMPv4 fragmentation needed message
// quoting a GUE packet sourced by katran and sent to katran's GUE source, as
// for parse_gue_ptb_v6
__attribute__((__always_inline__)) static inline bool
parse_gue_ptb_v4(void* data, void* data_end, __u64 off, struct gue_ptb* ptb) {
  struct iphdr* outer = data + sizeof(struct ethhdr);
  struct icmphdr* icmp_hdr = data + off;
  struct iphdr* iph = (void*)(icmp_hdr + 1);
  struct udphdr* udp = (void*)(iph + 1);
  if (outer + 1 > data_end || udp + 1 > data_end) {
    return false;
  }
  if (icmp_hdr->type != ICMP_DEST_UNREACH ||
      icmp_hdr->code != ICMP_FRAG_NEEDED || iph->version != 4 ||
      iph->ihl != 5 || iph->protocol != IPPROTO_UDP ||
      udp->dest != bpf_htons(GUE_DPORT)) {
    return false;
  }
  __u32 key = V4_SRC_INDEX;
  struct real_definition* src = bpf_map_lookup_elem(&pckt_srcs, &key);
  if (!src || src->dst != outer->daddr || src->dst != iph->saddr) {
    return false;
  }
  ptb->mtu = bpf_ntohs(icmp_hdr->un.frag.mtu);
  return parse_gue_ptb_inner(udp + 1, data_end, false, ptb);
}

/*
 * mtu to announce to the client, given the mtu the hop reported for the GUE
 * encapsulated packet:
 *   client mtu = hop mtu - outer ip header - udp header
 * i.e. 48 bytes less for an IPv6 outer header (40 + 8) and 28 bytes less for
 * an IPv4 one (20 + 8), whatever the client's family. GUE variant 1 adds no
 * header of its own between the udp header and the client's packet.
 * The result is then capped to the largest packet katran itself forwards,
 * MAX_PCKT_SIZE less the ethernet header, and raised to the minimum mtu of the
 * client's family: GUE_PTB_RELAY_MIN_MTU_V6 (1280) for IPv6, which leaves
 * clients on a tunnel path below 1328 unable to fit, and
 * GUE_PTB_RELAY_MIN_MTU_V4 (576) for IPv4.
 */
__attribute__((__always_inline__)) static inline __u32
gue_ptb_client_mtu(__u32 mtu, bool outer_ipv6, bool inner_ipv6) {
  __u32 overhead = sizeof(struct udphdr) +
      (outer_ipv6 ? sizeof(struct ipv6hdr) : sizeof(struct iphdr));
  __u32 min_mtu =
      inner_ipv6 ? GUE_PTB_RELAY_MIN_MTU_V6 : GUE_PTB_RELAY_MIN_MTU_V4;
  mtu = mtu > overhead ? mtu - overhead : 0;
  if (mtu > MAX_PCKT_SIZE - sizeof(struct ethhdr)) {
    mtu = MAX_PCKT_SIZE - sizeof(struct ethhdr);
  }
  if (mtu < min_mtu) {
    mtu = min_mtu;
  }
  return mtu;
}

// strips everything in front of the client's packet quoted in the PTB, which
// leaves the frame katran got from the client, and answers it with a PTB.
// returns XDP_DROP if adjusting the packet fails: by then the PTB may already
// be rewritten, and XDP_DROP_CNTR is the only counter which records it
__attribute__((__always_inline__)) static inline int
send_gue_ptb(struct xdp_md* xdp, bool outer_ipv6, bool inner_ipv6, __u32 mtu) {
  void* data = (void*)(long)xdp->data;
  void* data_end = (void*)(long)xdp->data_end;
  int hdrs = outer_ipv6 ? GUE_PTB_HDRS_V6 : GUE_PTB_HDRS_V4;
  struct ethhdr* old_eth = data;
  struct ethhdr* new_eth = data + hdrs;
  if (new_eth + 1 > data_end) {
    return XDP_DROP;
  }
  memcpy(new_eth->h_source, old_eth->h_source, ETH_ALEN);
  memcpy(new_eth->h_dest, old_eth->h_dest, ETH_ALEN);
  new_eth->h_proto = inner_ipv6 ? BE_ETH_P_IPV6 : BE_ETH_P_IP;
  if (XDP_ADJUST_HEAD_FUNC(xdp, hdrs)) {
    return XDP_DROP;
  }
  __u64 pckt_size = PCKT_DATA_LEN(xdp);
  // without frags support the length is data_end - data. keeps clang from
  // narrowing that to 32 bit math on the packet pointers, which the verifier
  // rejects
  asm volatile("" : "+r"(pckt_size));
  return send_icmp_too_big(xdp, inner_ipv6, pckt_size, mtu);
}

/*
 * Relays the ICMP packet at off if it is a PTB quoting a GUE packet katran
 * sent. Returns FURTHER_PROCESSING for any packet it does not handle, which
 * then takes the regular path.
 *
 * A static noinline subprog, so the verifier drops its stack frame on return
 * and every way of not relaying reaches process_packet in the same state.
 * Inlined, each early return leaves different stack and registers behind
 * which 7.1 kernels do not prune as equivalent, so the rest of process_packet
 * is verified once per return and the program exceeds the 1M instruction
 * limit. Splitting the function per address family would not help: inlined,
 * is_ipv6 is already constant on every path. Not a global function: a global
 * function that can change packet data invalidates every packet pointer of its
 * caller after each call, whichever path it took.
 */
__attribute__((noinline)) static int
handle_gue_ptb(struct xdp_md* xdp, __u64 off, bool is_ipv6) {
  void* data = (void*)(long)xdp->data;
  void* data_end = (void*)(long)xdp->data_end;
  struct gue_ptb ptb = {};
  struct vip_definition vip = {};
  if (is_ipv6 ? !parse_gue_ptb_v6(data, data_end, off, &ptb)
              : !parse_gue_ptb_v4(data, data_end, off, &ptb)) {
    return FURTHER_PROCESSING;
  }
  if (ptb.truncated) {
    incr_gue_ptb_relay_stats(GUE_PTB_RELAY_TRUNCATED_CNTR, is_ipv6);
    return FURTHER_PROCESSING;
  }

  if (!lookup_vip(&vip, &ptb.flow, ptb.inner_ipv6)) {
    return FURTHER_PROCESSING;
  }

  __u32 mtu = gue_ptb_client_mtu(ptb.mtu, is_ipv6, ptb.inner_ipv6);
  if (mtu >= ptb.pckt_len) {
    incr_gue_ptb_relay_stats(GUE_PTB_RELAY_NOT_NEEDED_CNTR, is_ipv6);
    return FURTHER_PROCESSING;
  }
  int action = send_gue_ptb(xdp, is_ipv6, ptb.inner_ipv6, mtu);
  if (action == XDP_TX) {
    incr_gue_ptb_relay_stats(GUE_PTB_RELAYED_CNTR, is_ipv6);
  }
  return action;
}

#endif // of __HANDLE_GUE_PTB_H
