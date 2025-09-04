// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#ifdef KATRAN_CMAKE_BUILD
#include "vmlinux.h"
#else
#include <bpf/vmlinux/vmlinux.h>
#endif

#include <bpf/bpf_helpers.h>

#include "tcp_pkt_router_common.h"
#include "tcp_pkt_router_consts.h"
#include "tcp_pkt_router_maps.h"
#include "tcp_pkt_router_structs.h"

const volatile __u8 KDE_ZONE_ALL = 0xFF;

static inline bool should_ignore_due_to_kde(struct bpf_sock_ops* skops) {
  __u32 sinfo_key = SERVER_INFO_INDEX;
  struct server_info* s_info = bpf_map_lookup_elem(&server_infos, &sinfo_key);
  // if kde is enabled, check if zone in hdr opts is matching server zone
  if (s_info && s_info->kde_enabled) {
    __u64 load_flags = BPF_LOAD_HDR_OPT_TCP_SYN;
    struct kde_clt_tcp_opt_v2 kde_opt = {};
    kde_opt.kind = KDE_CLT_TCP_HDR_OPT_KIND;
    int ret = bpf_load_hdr_opt(skops, &kde_opt, sizeof(kde_opt), load_flags);
    if (ret == KDE_CLT_TCP_HDR_OPT_V2_LEN) {
      if (s_info->kde_zones) {
        if ((s_info->kde_zones & kde_opt.zone) == kde_opt.zone) {
          return true;
        } else if (s_info->kde_zones == KDE_ZONE_ALL) {
          return true;
        }
      }
    }
  }
  return false;
}

static inline int handle_passive_parse_hdr(
    struct bpf_sock_ops* skops,
    struct stats* stat,
    const struct server_info* s_info) {
  int err;
  struct tcp_opt hdr_opt = {};

  hdr_opt.kind = TCP_HDR_OPT_KIND;
  err = bpf_load_hdr_opt(skops, &hdr_opt, sizeof(hdr_opt), NO_FLAGS);
  if (err < 0) {
    // peer didn't write anything.
    TPR_PRINT(skops, "passive parsed hdr found no option");
    stat->no_tcp_opt_hdr++;
    return err;
  }
  if (!hdr_opt.server_id) {
    // no server_id received from peer.
    stat->error_server_id_zero++;
    TPR_PRINT(skops, "passive received 0 server id");
    return PASS;
  }
  // Check if incoming server_id matches either primary or fallback server_id
  if (s_info->server_id != hdr_opt.server_id &&
      s_info->server_id_fallback != hdr_opt.server_id) {
    // read the server_id. But not itself. Packet is misrouted.
    stat->error_bad_id++;
    TPR_PRINT(
        skops,
        "passive received wrong server id: option=%d, server=%d, fallback=%d",
        hdr_opt.server_id,
        s_info->server_id,
        s_info->server_id_fallback);
    return PASS;
  } else {
    stat->server_id_read++;
    TPR_PRINT(skops, "passive received server-id option");
    // no need to keep writing this once peer sends the right server_id.
    err = unset_parse_hdr_cb_flags(skops, stat);
    err |= unset_write_hdr_cb_flags(skops, stat);
    return err;
  }
  return SUCCESS;
}

static inline int handle_passive_write_hdr_opt(
    struct bpf_sock_ops* skops,
    struct stats* stat,
    const struct server_info* s_info) {
  if (should_ignore_due_to_kde(skops)) {
    stat->ignoring_due_to_kde++;
    return SUCCESS;
  }

  int err;
  struct tcp_opt hdr_opt = {};

  hdr_opt.kind = TCP_SRV_HDR_OPT_KIND;
  hdr_opt.len = TCP_HDR_OPT_LEN;
  // If server_id is non-zero, use it; otherwise use server_id_fallback
  if (s_info->server_id != 0) {
    hdr_opt.server_id = s_info->server_id;
  } else {
    hdr_opt.server_id = s_info->server_id_fallback;
  }
  err = bpf_store_hdr_opt(skops, &hdr_opt, sizeof(hdr_opt), NO_FLAGS);
  if (err) {
    stat->error_write_opt++;
    return err;
  }
  stat->server_id_set++;
  TPR_PRINT(skops, "passive wrote option");
  return SUCCESS;
}

static inline int handle_passive_estab(
    struct bpf_sock_ops* skops,
    struct stats* stat,
    const struct server_info* s_info) {
  int err;
  struct tcp_opt hdr_opt = {};

  // check if received packet from peer has the right server_id
  hdr_opt.kind = TCP_HDR_OPT_KIND;
  err = bpf_load_hdr_opt(skops, &hdr_opt, sizeof(struct tcp_opt), NO_FLAGS);
  if (err < 0) {
    stat->no_tcp_opt_hdr++;
    TPR_PRINT(skops, "passive estab found no option");
    // since the peer didn't send any header, likely it doesn't support it.
    unset_write_hdr_cb_flags(skops, stat);
    unset_parse_hdr_cb_flags(skops, stat);
    return err;
  }
  // Check if incoming server_id matches either primary or fallback server_id
  if (s_info->server_id != hdr_opt.server_id &&
      s_info->server_id_fallback != hdr_opt.server_id) {
    stat->error_bad_id++;
    // the peer sent the server_id but it is wrong.
    // keep on sending the server_id and reading peer's tcp-hdr
    TPR_PRINT(
        skops,
        "passive estab received wrong server id: option=%d, server=%d, fallback=%d",
        hdr_opt.server_id,
        s_info->server_id,
        s_info->server_id_fallback);
    return set_parse_hdr_cb_flags(skops, stat);
  } else {
    stat->server_id_read++;
  }
  // no need to keep writing this once the connection is established.
  err = unset_parse_hdr_cb_flags(skops, stat);
  err |= unset_write_hdr_cb_flags(skops, stat);
  return err;
}
