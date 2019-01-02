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

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/string.h>

#include "bpf.h"
#include "bpf_helpers.h"

#define CTRL_MAP_SIZE 4
#define REALS_MAP_SIZE 4096
#define REDIRECT_EGRESS 0
#define DEFAULT_TTL 64

#define V6DADDR (1 << 0)

struct hc_real_definition {
  union {
    __be32 daddr;
    __be32 v6daddr[4];
  };
  __u8 flags;
};

struct bpf_map_def SEC("maps") hc_ctrl_map = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(__u32),
  .max_entries = CTRL_MAP_SIZE,
};

struct bpf_map_def SEC("maps") hc_reals_map = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct hc_real_definition),
  .max_entries = REALS_MAP_SIZE,
};

SEC("cls-hc")
int healthchecker(struct __sk_buff *skb)
{
  int ret = 0;
  int tun_flag = 0;
  __u32 ifindex;
  __u32 somark = skb->mark;
  __u32 v4_intf_pos = 1;
  __u32 v6_intf_pos = 2;
  struct bpf_tunnel_key tkey = {};

  if (skb->mark == 0) {
    return TC_ACT_UNSPEC;
  }

  struct hc_real_definition *real = bpf_map_lookup_elem(&hc_reals_map,
                                                     &somark);
  if(!real) {
    // some strange (w/ fwmark; but not a healthcheck)
    // local packet to the VIP.
    return TC_ACT_UNSPEC;
  }

  __u32 *v4_intf_ifindex = bpf_map_lookup_elem(&hc_ctrl_map,
                                               &v4_intf_pos);
  if (!v4_intf_ifindex) {
    // we dont have ifindex for ipip v4 interface
    // not much we can do w/o it. we will drop packet so hc would fail
    return TC_ACT_SHOT;
  }

  __u32 *v6_intf_ifindex = bpf_map_lookup_elem(&hc_ctrl_map,
                                               &v6_intf_pos);
  if (!v6_intf_ifindex) {
    // ditto
    return TC_ACT_SHOT;
  }

  tkey.tunnel_ttl = DEFAULT_TTL;

  // to prevent recursion, when encaped packed would run thru this filter
  skb->mark = 0;

  if(real->flags == V6DADDR) {
    //the dst is v6.
    tun_flag = BPF_F_TUNINFO_IPV6;
    memcpy(tkey.remote_ipv6, real->v6daddr, 16);
    ifindex = *v6_intf_ifindex;
  } else {
    //the dst is v4
    tkey.remote_ipv4 = real->daddr;
    ifindex = *v4_intf_ifindex;

  }

  bpf_skb_set_tunnel_key(skb, &tkey, sizeof(tkey), tun_flag);
  return bpf_redirect(ifindex, REDIRECT_EGRESS);
}

char _license[] SEC("license") = "GPL";
