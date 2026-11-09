#pragma once

#include <bpf/bpf_helpers.h>
#include <bpf/vmlinux/vmlinux.h>
#include <katran/kde/bpf/kde_constants.h>
#include <katran/kde/bpf/kde_maps.h>
#include <katran/kde/bpf/kde_types.h>

extern const volatile union kde_ip_address g_direct_ip;
extern struct kde_stats g_stats[MAX_CPUS];
const volatile __u8 g_kde_server_zones = KDE_ZONE_ALL;
const volatile __u8 g_vip_filter_mode = KDE_VIP_FILTER_NONE;
const volatile __u8 g_vips_enabled_cnt = 0;
const volatile __u8 g_vips_disabled_cnt = 0;
const volatile union kde_ip_address g_vips_enabled[KDE_MAX_VIPS_FILTER] = {};
const volatile union kde_ip_address g_vips_disabled[KDE_MAX_VIPS_FILTER] = {};

static inline int srv_handle_tcp_listen(
    struct bpf_sock_ops* skops,
    __u32 cpu_num) {
  int true_val = 1;
  int err = bpf_setsockopt(
      skops, IPPROTO_TCP, TCP_SAVE_SYN, &true_val, sizeof(true_val));
  if (err) {
    KDE_STAT_INC(server_error_setso);
    return CG_ERR;
  }
  err = bpf_sock_ops_cb_flags_set(
      skops, skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
  if (err) {
    KDE_STAT_INC(server_error_set_cb);
  }
  return CG_OK;
}

static inline bool pass_vip_filter(struct bpf_sock_ops* skops) {
  if (g_vip_filter_mode == KDE_VIP_FILTER_NONE) {
    return true;
  } else if (g_vip_filter_mode == KDE_VIP_FILTER_ALLOWLIST) {
#pragma unroll
    for (int i = 0; i < KDE_MAX_VIPS_FILTER; i++) {
      if (i >= g_vips_enabled_cnt) {
        return false;
      }
      if (skops->local_ip6[0] == g_vips_enabled[i].v6addr[0] &&
          skops->local_ip6[1] == g_vips_enabled[i].v6addr[1] &&
          skops->local_ip6[2] == g_vips_enabled[i].v6addr[2] &&
          skops->local_ip6[3] == g_vips_enabled[i].v6addr[3]) {
        return true;
      }
    }
    return false;
  } else if (g_vip_filter_mode == KDE_VIP_FILTER_BLOCKLIST) {
#pragma unroll
    for (int i = 0; i < KDE_MAX_VIPS_FILTER; i++) {
      if (i >= g_vips_disabled_cnt) {
        return true;
      }
      if (skops->local_ip6[0] == g_vips_disabled[i].v6addr[0] &&
          skops->local_ip6[1] == g_vips_disabled[i].v6addr[1] &&
          skops->local_ip6[2] == g_vips_disabled[i].v6addr[2] &&
          skops->local_ip6[3] == g_vips_disabled[i].v6addr[3]) {
        return false;
      }
    }
    return true;
  } else { // default
    return true;
  }
}

static inline bool has_syn_with_kde_opt(
    struct bpf_sock_ops* skops,
    __u32 cpu_num,
    bool* contains_nat_opt) {
  if ((skops->skb_tcp_flags & TCPHDR_SYNACK) != TCPHDR_SYNACK) {
    return false;
  }
  if (!pass_vip_filter(skops)) {
    return false;
  }
  /* called from both HDR_OPT_LEN_CB and WRITE_HDR_OPT_CB for every synack
   * (+ retrans); count only in HDR_OPT_LEN_CB to avoid double counting */
  bool count_stats = skops->op == BPF_SOCK_OPS_HDR_OPT_LEN_CB;
  __u64 load_flags = BPF_LOAD_HDR_OPT_TCP_SYN;
  struct kde_clt_tcp_opt kde_opt = {};
  kde_opt.kind = KDE_CLT_TCP_HDR_OPT_KIND;
  int ret = bpf_load_hdr_opt(
      skops, &kde_opt, KDE_CLT_TCP_HDR_NAT_OPT_LEN, load_flags);
  if (ret == -ENOMSG) { // option not found
    if (count_stats) {
      KDE_STAT_INC(server_no_kde);
    }
    return false;
  }
  if (ret == -ENOENT) { // no syn saved
    if (count_stats) {
      KDE_STAT_INC(server_error_no_saved_syn);
    }
    return false;
  }
  if (ret != KDE_CLT_TCP_HDR_OPT_LEN && ret != KDE_CLT_TCP_HDR_NAT_OPT_LEN) {
    if (count_stats) {
      KDE_STAT_INC(server_error_load_hdr);
    }
    return false;
  }

  if (ret == KDE_CLT_TCP_HDR_NAT_OPT_LEN && contains_nat_opt) {
    *contains_nat_opt = kde_opt.nat_support;
  }
  bool zone_match = (g_kde_server_zones & kde_opt.zone) ||
      (g_kde_server_zones == KDE_ZONE_ALL);
  if (!count_stats) {
    return zone_match;
  }

  if ((kde_opt.zone & KDE_ZONE_1) == KDE_ZONE_1) {
    if (zone_match) {
      KDE_STAT_INC(server_rx_zone_1_acc);
    } else {
      KDE_STAT_INC(server_rx_zone_1_rej);
    }
  } else if ((kde_opt.zone & KDE_ZONE_2) == KDE_ZONE_2) {
    if (zone_match) {
      KDE_STAT_INC(server_rx_zone_2_acc);
    } else {
      KDE_STAT_INC(server_rx_zone_2_rej);
    }
  } else if ((kde_opt.zone & KDE_ZONE_3) == KDE_ZONE_3) {
    if (zone_match) {
      KDE_STAT_INC(server_rx_zone_3_acc);
    } else {
      KDE_STAT_INC(server_rx_zone_3_rej);
    }
  } else if ((kde_opt.zone & KDE_ZONE_4) == KDE_ZONE_4) {
    if (zone_match) {
      KDE_STAT_INC(server_rx_zone_4_acc);
    } else {
      KDE_STAT_INC(server_rx_zone_4_rej);
    }
  } else {
    if (zone_match) {
      KDE_STAT_INC(server_rx_zone_unknown_acc);
    } else {
      KDE_STAT_INC(server_rx_zone_unknown_rej);
    }
  }
  return zone_match;
}

static inline int srv_handle_hdr_opt_len(
    struct bpf_sock_ops* skops,
    __u32 cpu_num) {
  if (!has_syn_with_kde_opt(skops, cpu_num, /*contains_nat_opt=*/NULL)) {
    KDE_STAT_INC(server_no_kde_syn);
    return CG_OK;
  }
  int err = bpf_reserve_hdr_opt(skops, sizeof(struct kde_srv_tcp_opt), 0);
  if (err) {
    KDE_STAT_INC(server_error_reserve);
    return CG_ERR;
  }
  return CG_OK;
}

static inline int srv_handle_write_hdr_opt(
    struct bpf_sock_ops* skops,
    __u32 cpu_num) {
  bool contains_nat_opt = false;
  if (!has_syn_with_kde_opt(skops, cpu_num, &contains_nat_opt)) {
    return CG_OK;
  }

  struct kde_srv_tcp_opt hdr_opt = {};
  hdr_opt.kind = KDE_SRV_TCP_HDR_OPT_KIND;
  /* old clients would still read 18B, and 20B would fail with ENOSPC.
   * write 20B only when client requested */
  __u32 opt_len = KDE_SRV_TCP_HDR_OPT_LEN;
  hdr_opt.v6addr[0] = g_direct_ip.v6addr[0];
  hdr_opt.v6addr[1] = g_direct_ip.v6addr[1];
  hdr_opt.v6addr[2] = g_direct_ip.v6addr[2];
  hdr_opt.v6addr[3] = g_direct_ip.v6addr[3];

  if (contains_nat_opt) {
    hdr_opt.client_port = bpf_htons(bpf_ntohl(skops->remote_port));
    opt_len = KDE_SRV_TCP_HDR_NAT_OPT_LEN;
  }
  hdr_opt.len = opt_len;

  int err = bpf_store_hdr_opt(skops, &hdr_opt, opt_len, NO_FLAGS);
  if (err) {
    KDE_STAT_INC(server_error_write_opt);
    return CG_ERR;
  }

  /* update the map to check synack retrans
   * at current syn-ack rate, shared cpu is sufficient. if profiling shows
   * contention, consider cpu sharded lru maps. */
  struct tuple tuple_key = {};
  make_tuple(skops, &tuple_key);
  __u8 int_retrans = 0;
  __u8* retrans = bpf_map_lookup_elem(&kde_synack_map, &tuple_key);
  if (retrans == NULL) { // first synack, not retrans
    err = bpf_map_update_elem(
        &kde_synack_map, &tuple_key, &int_retrans, BPF_NOEXIST);
    if (err && err != -EEXIST) {
      KDE_STAT_INC(server_error_synack_map_update);
    }
  } else { // synack retrans
    KDE_STAT_INC(server_retrans_synack);
    /* default kernel synack retries is 5, setting it to 3 because:
     * - default synack retries are reduced under pressure
     * - due to exponential backoff, 5th retrans is hit 4x after 3rd retrans.
     *   lru experiences more pressure and risks undercounting  */
    if (++(*retrans) == 3) {
      KDE_STAT_INC(server_directip_blackhole);
    }
  }

  KDE_STAT_INC(server_opt_set);
  if (contains_nat_opt) {
    KDE_STAT_INC(server_nat_opt_set);
  }
  return CG_OK;
}

static inline int srv_unset_write_hdr_cb_flags(
    struct bpf_sock_ops* skops,
    __u32 cpu_num) {
  int err = bpf_sock_ops_cb_flags_set(
      skops,
      skops->bpf_sock_ops_cb_flags & ~BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
  if (err) {
    KDE_STAT_INC(server_error_unset_cb);
    return CG_ERR;
  }
  return CG_OK;
}

static inline int srv_handle_passive_estab(
    struct bpf_sock_ops* skops,
    __u32 cpu_num) {
  struct tuple key = {};
  make_tuple(skops, &key);
  int err = bpf_map_delete_elem(&kde_synack_map, &key);
  if (err && err != -ENOENT) {
    KDE_STAT_INC(server_error_synack_map_update);
  }
  return srv_unset_write_hdr_cb_flags(skops, cpu_num);
}

static inline int handle_server(struct bpf_sock_ops* skops, __u32 cpu_num) {
  if (skops->family != AF_INET6) {
    return CG_OK;
  }
  switch (skops->op) {
    case BPF_SOCK_OPS_TCP_LISTEN_CB:
      // Set the WRITE_HDR_OPT_CB now to write direct IP on SYN-ACK
      return srv_handle_tcp_listen(skops, cpu_num);
    case BPF_SOCK_OPS_HDR_OPT_LEN_CB:
      // Reserve space for writing the header option later in
      // BPF_SOCK_OPS_WRITE_HDR_OPT_CB.
      return srv_handle_hdr_opt_len(skops, cpu_num);
    case BPF_SOCK_OPS_WRITE_HDR_OPT_CB:
      // Write the direct IP as hdr-opt
      return srv_handle_write_hdr_opt(skops, cpu_num);
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
      // once the connection is estd, unset handlers as we only write for
      // SYN-ACKs
      return srv_handle_passive_estab(skops, cpu_num);
    default:
      return CG_OK;
  }
}
