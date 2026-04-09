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

#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stdbool.h>
#include <stddef.h>

#include "katran/lib/linux_includes/bpf.h"
#include "katran/lib/linux_includes/bpf_endian.h"
#include "katran/lib/linux_includes/bpf_helpers.h"

#include "katran/lib/bpf/balancer_consts.h"

/*
 * Used when client sends packets behind a SNATs (like cilium in k8s). SNATs
 * usually overwrite the src ip of the outer packet; while inner packet still
 * holds the container ip. This can break the connection state in servers. To
 * allow such clients, we use the SNATed ip as the source of truth, and
 * overwrite the inner packet's src ip to match outer packet.
 *
 * This also helps in enforcing some level of security where a malicious client
 * sends packet with a valid outer src ip, and the spoofed inner src ip. FWs
 * usually only look at outer packets, allowing the packet to pass thru.
 *
 * NON invasive = does not terminate progs. Chain and run before a tc decap
 * prog.
 */
SEC("tc") int tc_srcmatch(struct __sk_buff* skb) {
  void* data = (void*)(long)skb->data;
  void* data_end = (void*)(long)skb->data_end;

  if (data + sizeof(struct ethhdr) > data_end) {
    return TC_ACT_SHOT;
  }

  struct ethhdr* eth = data;
  if (eth + 1 > data_end || eth->h_proto != BE_ETH_P_IPV6) {
    return TC_ACT_PIPE;
  }

  struct ipv6hdr* o_ip6hdr = data + sizeof(struct ethhdr);
  if (o_ip6hdr + 1 > data_end || o_ip6hdr->nexthdr != IPPROTO_UDP) {
    return TC_ACT_PIPE;
  }

  struct udphdr* udp_hdr =
      data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
  if (udp_hdr + 1 > data_end || udp_hdr->dest != bpf_htons(KDE_GUE_PORT)) {
    return TC_ACT_PIPE;
  }

  __u8* i_ipv6_proto = data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) +
      sizeof(struct udphdr);
  if (i_ipv6_proto + 1 > data_end || !(*i_ipv6_proto & GUEV1_IPV6MASK)) {
    return TC_ACT_PIPE;
  }

  struct ipv6hdr* i_ip6hdr = data + sizeof(struct ethhdr) +
      sizeof(struct ipv6hdr) + sizeof(struct udphdr);
  if (i_ip6hdr + 1 > data_end || i_ip6hdr->nexthdr != IPPROTO_TCP) {
    return TC_ACT_PIPE;
  }

  __u64 tcp_csum_offset = sizeof(struct ethhdr) + sizeof(struct ipv6hdr) +
      sizeof(struct udphdr) + sizeof(struct ipv6hdr) +
      offsetof(struct tcphdr, check);

  // Copy o_saddr to stack; bpf_skb_store_bytes can't read from packet memory
  struct in6_addr o_saddr = o_ip6hdr->saddr;
  struct in6_addr i_saddr = i_ip6hdr->saddr;
#pragma unroll
  for (int i = 0; i < 4; i++) {
    bpf_l4_csum_replace(
        /*skb=*/skb,
        /*offset=*/tcp_csum_offset,
        /*from=*/i_saddr.in6_u.u6_addr32[i],
        /*to=*/o_saddr.in6_u.u6_addr32[i],
        /*flags=*/4); // 4-byte replacement
  }

  __u64 i_ip6hdr_src_offset = sizeof(struct ethhdr) + sizeof(struct ipv6hdr) +
      sizeof(struct udphdr) + offsetof(struct ipv6hdr, saddr);

  bpf_skb_store_bytes(
      /*skb=*/skb,
      /*offset=*/i_ip6hdr_src_offset,
      /*from=*/&o_saddr,
      /*len=*/sizeof(struct in6_addr),
      /*flags=*/BPF_F_RECOMPUTE_CSUM // as we change src
  );

  return TC_ACT_PIPE;
}

char _license[] SEC("license") = "GPL";
