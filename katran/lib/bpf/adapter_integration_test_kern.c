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

#include <linux/in.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_tunnel.h>
#include <linux/pkt_cls.h>

#include "bpf.h"
#include "bpf_helpers.h"

#define CTRL_ARRAY_SIZE 2
#define CNTRS_ARRAY_SIZE 512



/*
 * map_fd #0
 */

struct bpf_map_def SEC("maps") ctl_array = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(__u32),
  .max_entries = CTRL_ARRAY_SIZE,
};


/*
 * map_fd #1
 */
struct bpf_map_def SEC("maps") cntrs_array = {
 // @lint-ignore TXT2 T25377293 Grandfathered in
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(__u64),
  .max_entries = CNTRS_ARRAY_SIZE,
};

SEC("cls-pktcntr")
int pktcntr(struct __sk_buff *skb) {
  __u32 ctl_flag_pos = 0;
  __u32 cntr_pos = 0;
  __u32* flag = bpf_map_lookup_elem(&ctl_array, &ctl_flag_pos);

  if (!flag || (*flag == 0)) {
    return TC_ACT_OK;
  };


  __u64* cntr_val = bpf_map_lookup_elem(&cntrs_array, &cntr_pos);
  if (cntr_val) {
    *cntr_val += 1;
  };
  return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
