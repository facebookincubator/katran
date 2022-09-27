// (c) Facebook, Inc. and its affiliates. Confidential and proprietary.

#pragma once

#ifdef KATRAN_CMAKE_BUILD
#include "vmlinux.h"
#else
#include <bpf/vmlinux/vmlinux.h>
#endif

#include <bpf/bpf_helpers.h>

#include "tcp_pkt_router_consts.h"
#include "tcp_pkt_router_maps.h"
#include "tcp_pkt_router_structs.h"

#define _LIKELY(expr) __builtin_expect(!!(expr), 1)
#define _UNLIKELY(expr) __builtin_expect(!!(expr), 0)

static inline int set_write_hdr_cb_flags(
    struct bpf_sock_ops* skops,
    struct stats* stat) {
  int err = bpf_sock_ops_cb_flags_set(
      skops, skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
  if (err) {
    stat->error_sys_calls++;
  }
  return err;
}

static inline int unset_write_hdr_cb_flags(
    struct bpf_sock_ops* skops,
    struct stats* stat) {
  int err = bpf_sock_ops_cb_flags_set(
      skops,
      skops->bpf_sock_ops_cb_flags & ~BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
  if (err) {
    stat->error_sys_calls++;
  }
  return err;
}

static inline int set_parse_hdr_cb_flags(
    struct bpf_sock_ops* skops,
    struct stats* stat) {
  int err = bpf_sock_ops_cb_flags_set(
      skops,
      skops->bpf_sock_ops_cb_flags |
          BPF_SOCK_OPS_PARSE_UNKNOWN_HDR_OPT_CB_FLAG);
  if (err) {
    stat->error_sys_calls++;
  }
  return err;
}

static inline int unset_parse_hdr_cb_flags(
    struct bpf_sock_ops* skops,
    struct stats* stat) {
  int err = bpf_sock_ops_cb_flags_set(
      skops,
      skops->bpf_sock_ops_cb_flags &
          ~BPF_SOCK_OPS_PARSE_UNKNOWN_HDR_OPT_CB_FLAG);
  if (err) {
    stat->error_sys_calls++;
  }
  return err;
}

static inline int handle_hdr_opt_len(
    struct bpf_sock_ops* skops,
    struct stats* stat) {
  int err = bpf_reserve_hdr_opt(skops, sizeof(struct tcp_opt), 0);
  if (err) {
    stat->error_sys_calls++;
  }
  return err;
}
