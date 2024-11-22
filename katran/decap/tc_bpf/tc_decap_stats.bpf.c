
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

__attribute__((__always_inline__)) static inline void validate_tpr_server_id(
    void* data,
    __u64 off,
    void* data_end,
    bool is_ipv6,
    struct __sk_buff* skb,
    struct decap_tpr_stats* data_stats) {
  __u16 inner_pkt_bytes;
  struct packet_description inner_pckt = {};
  if (process_l3_headers(data, data_end, off, is_ipv6, &inner_pckt.flow) >= 0) {
    return;
  }
  if (inner_pckt.flow.proto != IPPROTO_TCP) {
    return;
  }
  if (!parse_tcp(data, data_end, is_ipv6, &inner_pckt)) {
    return;
  }
  // only check for TCP non SYN packets
  if (!(inner_pckt.flags & F_SYN_SET)) {
    // lookup server id from tpr header option and compare against server_id on
    // this host (if available)
    __u32 s_key = 0;
    __u32* server_id_host = bpf_map_lookup_elem(&tpr_server_id, &s_key);
    if (server_id_host && *server_id_host > 0) {
      __u32 server_id = 0;
      tcp_hdr_opt_lookup_server_id_skb(skb, is_ipv6, &server_id);
      if (server_id > 0) {
        data_stats->tpr_total += 1;
        if (*server_id_host != server_id) {
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

__attribute__((__always_inline__)) static inline int process_packet(
    void* data,
    __u64 off,
    void* data_end,
    bool is_ipv6,
    struct __sk_buff* skb) {
  struct packet_description pckt = {};
  struct decap_tpr_stats* data_stats;
  __u32 key = 0;
  data_stats = bpf_map_lookup_elem(&tc_tpr_stats, &key);
  if (!data_stats) {
    return XDP_PASS;
  }
  validate_tpr_server_id(data, off, data_end, is_ipv6, skb, data_stats);
  return TC_ACT_UNSPEC;
}

SEC("tc")
int tcdecapstats(struct __sk_buff* skb) {
  void* data = (void*)(long)skb->data;
  void* data_end = (void*)(long)skb->data_end;
  __u32 eth_proto;
  struct ethhdr* eth = data;
  __u32 nh_off = sizeof(struct ethhdr);

  if (data + nh_off > data_end) {
    return TC_ACT_UNSPEC;
  }
  eth_proto = eth->h_proto;
  if (eth_proto == BE_ETH_P_IP) {
    return process_packet(data, nh_off, data_end, false, skb);
  } else if (eth_proto == BE_ETH_P_IPV6) {
    return process_packet(data, nh_off, data_end, true, skb);
  } else {
    return TC_ACT_UNSPEC;
  }
}

char _license[] SEC("license") = "GPL";
