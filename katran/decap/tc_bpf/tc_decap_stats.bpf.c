
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
#include "tc_decap_stats_maps.h"

#define PROTO_TCP_BIT 0
#define PROTO_UDP_BIT 1

#ifdef DECAP_TPR_STATS
__attribute__((__always_inline__)) static inline void validate_tpr_server_id(
    void* data,
    void* data_end,
    bool is_ipv6,
    struct __sk_buff* skb,
    struct decap_tpr_stats* data_stats) {
  struct packet_description pckt = {};
  if (!parse_tcp(data, data_end, is_ipv6, &pckt)) {
    return;
  }
  // only check for TCP non SYN packets
  if (!(pckt.flags & F_SYN_SET)) {
    // lookup server id from tpr header option and compare against server_id on
    // this host (if available)
    // there might be two different server ids from packets to different
    // processes during hotswap, so we check both
    __u32 s_key_0 = 0;
    __u32* server_id_0 = bpf_map_lookup_elem(&tpr_server_ids, &s_key_0);
    bool server_id_0_found = (server_id_0 && *server_id_0 > 0);
    __u32 s_key_1 = 1;
    __u32* server_id_1 = bpf_map_lookup_elem(&tpr_server_ids, &s_key_1);
    bool server_id_1_found = (server_id_1 && *server_id_1 > 0);
    if (server_id_0_found || server_id_1_found) {
      __u32 server_id = 0;
      tcp_hdr_opt_lookup_server_id_skb(skb, is_ipv6, &server_id);
      if (server_id > 0) {
        data_stats->tpr_total += 1;
        if ((!server_id_0_found || (*server_id_0 != server_id)) &&
            (!server_id_1_found || (*server_id_1 != server_id))) {
          data_stats->tpr_misrouted += 1;
          __u32 sid_sample_key = 0;
          __u64* server_id_sample =
              bpf_map_lookup_elem(&tpr_mism_sid, &sid_sample_key);
          if (server_id_sample) {
            *server_id_sample = server_id;
          }
        }
      }
    }
  }
}
#endif

__attribute__((__always_inline__)) static inline void incr_vip_stats(
    __u8 proto,
    bool is_ipv6) {
  __u32 key = proto == IPPROTO_TCP ? 0 : 1;
  struct vip_decap_stats* vip_stats = bpf_map_lookup_elem(&tc_vip_stats, &key);
  if (vip_stats) {
    if (is_ipv6) {
      vip_stats->v6_packets += 1;
    } else {
      vip_stats->v4_packets += 1;
    }
  }
}

__attribute__((__always_inline__)) static inline void incr_decap_vip_stats(
    void* data,
    void* data_end,
    struct pckt_addr_proto* pckt,
    bool is_ipv6) {
  struct vip_info* vip;
  if (is_ipv6) {
    if (pckt->ip6h + 1 > data_end) {
      return;
    }
    // We use pct->ip6h->daddr directly as a key to lookup in vip info map.
    // This saves us memcpy daddr to a new struct, especially since we are
    // calling this for every packet. The downside is that we can't use
    // daddr+port as key
    vip = bpf_map_lookup_elem(&tc_vip6_info, &pckt->ip6h->daddr.s6_addr32);
  } else {
    if (pckt->iph + 1 > data_end) {
      return;
    }
    vip = bpf_map_lookup_elem(&tc_vip4_info, &pckt->iph->daddr);
  }
  if (vip) {
    // check if dst protocol is expected for vip
    if (pckt->proto == IPPROTO_TCP && vip->proto_mask & (1 << PROTO_TCP_BIT)) {
      incr_vip_stats(pckt->proto, is_ipv6);
    } else if (
        pckt->proto == IPPROTO_UDP && vip->proto_mask & (1 << PROTO_UDP_BIT)) {
      incr_vip_stats(pckt->proto, is_ipv6);
    }
  }
  return;
}

__attribute__((__always_inline__)) static inline int process_packet(
    void* data,
    __u64 off,
    void* data_end,
    bool is_ipv6,
    struct __sk_buff* skb) {
  struct decap_tpr_stats* data_stats;
  __u32 key = 0;
  data_stats = bpf_map_lookup_elem(&tc_tpr_stats, &key);
  if (!data_stats) {
    return TC_ACT_UNSPEC;
  }
  struct pckt_addr_proto pckt_info = {};
  if (get_packet_addr_proto(data, data_end, off, is_ipv6, &pckt_info) !=
      DECAP_FURTHER_PROCESSING) {
    return TC_ACT_UNSPEC;
  }
#ifdef DECAP_TPR_STATS
  if (pckt_info.proto == IPPROTO_TCP) {
    validate_tpr_server_id(data, data_end, is_ipv6, skb, data_stats);
  }
#endif

#ifdef DECAP_VIP_STATS
  incr_decap_vip_stats(data, data_end, &pckt_info, is_ipv6);
#endif

  return TC_ACT_UNSPEC;
}

SEC("tc")
int tcdecapstats(struct __sk_buff* skb) {
  void* data = (void*)(long)skb->data;
  void* data_end = (void*)(long)skb->data_end;
  __u32 eth_proto;
  __u32 nh_off = sizeof(struct ethhdr);

  if (data + nh_off > data_end) {
    return TC_ACT_UNSPEC;
  }
  // Looking at decapped packet, skb->protocol has the correct protocol
  eth_proto = skb->protocol;
  if (eth_proto == BE_ETH_P_IP) {
    return process_packet(data, nh_off, data_end, false, skb);
  } else if (eth_proto == BE_ETH_P_IPV6) {
    return process_packet(data, nh_off, data_end, true, skb);
  } else {
    return TC_ACT_UNSPEC;
  }
  return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";
