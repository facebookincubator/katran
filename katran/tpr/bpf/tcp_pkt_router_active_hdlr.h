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

static inline int handle_active_parse_hdr(
    struct bpf_sock_ops* skops,
    struct stats* stat) {
  int err;
  struct tcp_opt hdr_opt = {};

  hdr_opt.kind = TCP_HDR_OPT_KIND;
  err = bpf_load_hdr_opt(skops, &hdr_opt, sizeof(struct tcp_opt), NO_FLAGS);
  if (err < 0) {
    // peer is not sending any tcp-hdr option. Likely doesn't support it.
    stat->no_tcp_opt_hdr++;
    unset_parse_hdr_cb_flags(skops, stat);
    unset_write_hdr_cb_flags(skops, stat);
    return err;
  }
  if (!hdr_opt.server_id) {
    stat->error_bad_id++;
    TPR_PRINT(skops, "active parsed empty server id from the option");
    return PASS;
  }

  struct bpf_sock* sk = skops->sk;
  if (_UNLIKELY(!sk)) {
    return PASS;
  }
  __u32* id = bpf_sk_storage_get(
      &sk_sid_store, sk, &hdr_opt.server_id, BPF_SK_STORAGE_GET_F_CREATE);
  if (_UNLIKELY(!id)) {
    stat->error_sys_calls++;
    return PASS;
  }

  if (*id == hdr_opt.server_id) {
    stat->server_id_read++;
    unset_parse_hdr_cb_flags(skops, stat);
  } else {
    if (*id) {
      TPR_PRINT(
          skops,
          "active parse diffrent id than in storage: header=%d, storage=%d",
          hdr_opt.server_id,
          *id);
      stat->error_bad_id++;
    }
    *id = hdr_opt.server_id;
    // Somehow it hit an error before, keep the parse_hdr_cb_flags.
    // The kernel will only call the bpf prog if there is indeed an unknown
    // option that the kernel cannot handle.
  }
  // no need to set_write_hdr_cb_flags() either. It has already been set.
  return SUCCESS;
}

static int handle_active_write_hdr_opt(
    struct bpf_sock_ops* skops,
    struct stats* stat) {
  int err;
  struct tcp_opt hdr_opt = {};

  struct bpf_sock* sk = skops->sk;
  if (_UNLIKELY(!sk)) {
    return PASS;
  }
  hdr_opt.kind = TCP_HDR_OPT_KIND;
  hdr_opt.len = TCP_HDR_OPT_LEN;
  __u32* existing_id = bpf_sk_storage_get(&sk_sid_store, sk, NULL, NO_FLAGS);
  if (_UNLIKELY(!existing_id)) {
    // If there's no existing id, it could be because sk_storage failed in
    // while storing 'hdr_opt.server_id'. Send id == 0 so that the passive
    // side can try sending back proper id in the next round.
    hdr_opt.server_id = 0;
    stat->error_bad_id++;
    TPR_PRINT(skops, "active failed to read server id from storage");
  } else {
    hdr_opt.server_id = *existing_id;
  }

  err = bpf_store_hdr_opt(skops, &hdr_opt, sizeof(hdr_opt), NO_FLAGS);
  if (err) {
    // NOTE err == -17 (EEXISTS) can happen if this hdr_opt.kind already exists
    // TODO: if this happens often, check for this specific error
    stat->error_write_opt++;
    return PASS;
  }
  stat->server_id_set++;
  return SUCCESS;
}

static inline int handle_active_estab(
    struct bpf_sock_ops* skops,
    struct stats* stat) {
  int err;
  struct tcp_opt hdr_opt = {};

  hdr_opt.kind = TCP_HDR_OPT_KIND;
  err = bpf_load_hdr_opt(skops, &hdr_opt, sizeof(struct tcp_opt), NO_FLAGS);
  if (err < 0) {
    // peer is not sending any tcp-hdr option. Likely doesn't support it.
    stat->no_tcp_opt_hdr++;
    // TODO revisit after getting some signal from prod: if there are lots of
    // cases where it can't read server_id upon this callback, then
    // we can try to keep reading via parse_hdr for some rounds
    err = unset_parse_hdr_cb_flags(skops, stat);
    err |= unset_write_hdr_cb_flags(skops, stat);
    return err;
  }
  if (_UNLIKELY(!hdr_opt.server_id)) {
    // Received tcp-hdr-opt but no server_id recv'ed from peer.
    stat->error_bad_id++;
    // write a server_id 0 out to tell passive side to resend its server_id
    set_write_hdr_cb_flags(skops, stat);
    // try to read in the next round
    set_parse_hdr_cb_flags(skops, stat);
    return PASS;
  }

  struct bpf_sock* sk = skops->sk;
  if (_UNLIKELY(!sk)) {
    return PASS;
  }
  // server_id received during the estd-phase takes precedence over others
  // if there's one already present (although this should almost never happen)
  __u32* id = bpf_sk_storage_get(
      &sk_sid_store, sk, &hdr_opt.server_id, BPF_SK_STORAGE_GET_F_CREATE);
  if (_UNLIKELY(!id || *id != hdr_opt.server_id)) {
    if (id) {
      // We somehow stored the wrong id which should not happen. Reset it to 0
      *id = 0;
      stat->error_bad_id++;
    } else {
      stat->error_sys_calls++;
    }
    // write a server_id 0 out to tell passive side to resend its server_id
    set_write_hdr_cb_flags(skops, stat);
    set_parse_hdr_cb_flags(skops, stat);
    return PASS;
  }
  // successful storage. Set write hdr for subsequent pkts
  err = set_write_hdr_cb_flags(skops, stat);
  if (err) {
    err |= set_parse_hdr_cb_flags(skops, stat);
    return err;
  }
  stat->server_id_read++;
  return SUCCESS;
}
