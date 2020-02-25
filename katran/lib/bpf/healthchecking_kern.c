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

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/string.h>
#include <linux/udp.h>

#include "bpf.h"
#include "bpf_helpers.h"

#include "encap_helpers.h"

#include "healthchecking_structs.h"
#include "healthchecking_helpers.h"
#include "healthchecking_maps.h"


SEC("cls-hc")
int healthchecker(struct __sk_buff *skb)
{
  __u32 stats_key = GENERIC_STATS_INDEX;
  __u32 key = HC_MAIN_INTF_POSITION;
  __u32 somark = skb->mark;
  __u32 ifindex = 0;
  __u64 flags = 0;
  bool is_ipv6 = false;
  int adjust_len = 0;
  int ret = 0;
  struct hc_stats* prog_stats;
  struct ethhdr* ethh;
  struct hc_mac *esrc, *edst;
  struct hc_real_definition *src;
  prog_stats = bpf_map_lookup_elem(&hc_stats_map, &stats_key);
  if (!prog_stats) {
    return TC_ACT_UNSPEC;
  }

  if (somark == 0) {
    prog_stats->pckts_skipped += 1;
    return TC_ACT_UNSPEC;
  }

  struct hc_real_definition *real = bpf_map_lookup_elem(&hc_reals_map,
                                                     &somark);
  if(!real) {
    // some strange (w/ fwmark; but not a healthcheck) local packet
    prog_stats->pckts_skipped += 1;
    return TC_ACT_UNSPEC;
  }

  if (skb->len > HC_MAX_PACKET_SIZE) {
    // do not allow packets bigger than the specified size
    prog_stats->pckts_dropped += 1;
    prog_stats->pckts_too_big += 1;
    return TC_ACT_SHOT;
  }

  __u32* intf_ifindex = bpf_map_lookup_elem(&hc_ctrl_map, &key);
  if (!intf_ifindex) {
    // we dont have ifindex for main interface
    // not much we can do without it. Drop packet so that hc will fail
    prog_stats->pckts_dropped += 1;
    return TC_ACT_SHOT;
  }

  key = HC_SRC_MAC_POS;
  esrc = bpf_map_lookup_elem(&hc_pckt_macs, &key);
  if (!esrc) {
    prog_stats->pckts_dropped += 1;
    return TC_ACT_SHOT;
  }

  key = HC_DST_MAC_POS;
  edst = bpf_map_lookup_elem(&hc_pckt_macs, &key);
  if (!edst) {
    prog_stats->pckts_dropped += 1;
    return TC_ACT_SHOT;
  }

  if ((skb->data + sizeof(struct ethhdr)) > skb->data_end) {
    prog_stats->pckts_dropped += 1;
    return TC_ACT_SHOT;
  }

  ethh = (void*)(long)skb->data;
  if (ethh->h_proto == BE_ETH_P_IPV6) {
    is_ipv6 = true;
  }

  // to prevent recursion, if encapsulated packet would run through this filter
  skb->mark = 0;

  if (!HC_ENCAP(skb, real, ethh, is_ipv6)) {
    prog_stats->pckts_dropped += 1;
    return TC_ACT_SHOT;
  }

  if (skb->data + sizeof(struct ethhdr) > skb->data_end) {
    prog_stats->pckts_dropped += 1;
    return TC_ACT_SHOT;
  }

  ethh = (void*)(long)skb->data;
  memcpy(ethh->h_source, esrc->mac, 6);
  memcpy(ethh->h_dest, edst->mac, 6);

  prog_stats->pckts_processed += 1;
  return bpf_redirect(*intf_ifindex, REDIRECT_EGRESS);
}

char _license[] SEC("license") = "GPL";
