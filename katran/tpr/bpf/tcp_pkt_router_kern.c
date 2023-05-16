// Copyright (c) Meta Platforms, Inc. and affiliates.

#ifdef KATRAN_CMAKE_BUILD
#include "vmlinux.h"
#else
#include <bpf/vmlinux/vmlinux.h>
#endif

#include <bpf/bpf_helpers.h>

#include "tcp_pkt_router_active_hdlr.h"
#include "tcp_pkt_router_common.h"
#include "tcp_pkt_router_consts.h"
#include "tcp_pkt_router_maps.h"
#include "tcp_pkt_router_passive_hdlr.h"
#include "tcp_pkt_router_structs.h"

static inline int handle_passive_cb(
    struct bpf_sock_ops* skops,
    struct stats* stat,
    const struct server_info* s_info) {
  TPR_PRINT(skops, "passive cb", skops->op);
  int err;

  switch (skops->op) {
    case BPF_SOCK_OPS_TCP_LISTEN_CB:
      // server mode does not need to read anything.
      // Set the WRITE_HDR_OPT_CB now to write server-id on SYN-ACK
      // TODO: check if the peer supports hdr-opt and disable writing?
      return set_write_hdr_cb_flags(skops, stat);
    case BPF_SOCK_OPS_PARSE_HDR_OPT_CB:
      /* Read hdr-opt sent by the active side.
       * Only for the packets received after 3WHS */
      return handle_passive_parse_hdr(skops, stat, s_info);
    case BPF_SOCK_OPS_HDR_OPT_LEN_CB:
      /* Reserve space for writing the header option later in
       * BPF_SOCK_OPS_WRITE_HDR_OPT_CB. */
      if ((skops->skb_tcp_flags & TCPHDR_SYNACK) == TCPHDR_SYNACK) {
        return handle_hdr_opt_len(skops, stat);
      } else {
        return SUCCESS;
      }
    case BPF_SOCK_OPS_WRITE_HDR_OPT_CB:
      /* Write the server-id as hdr-opt */
      if ((skops->skb_tcp_flags & TCPHDR_SYNACK) == TCPHDR_SYNACK) {
        return handle_passive_write_hdr_opt(skops, stat, s_info);
      } else {
        return SUCCESS;
      }
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
      /* once the connection is estd, stop writing server-id */
      return handle_passive_estab(skops, stat, s_info);
    case BPF_SOCK_OPS_TCP_CONNECT_CB:
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
    default:
      break;
  }
  return SUCCESS;
}

static inline int handle_active_cb(
    struct bpf_sock_ops* skops,
    struct stats* stat) {
  TPR_PRINT(skops, "active cb", skops->op);
  switch (skops->op) {
    case BPF_SOCK_OPS_TCP_CONNECT_CB:
      /* Called before SYN is sent on active side: nth to do */
      break;
    case BPF_SOCK_OPS_PARSE_HDR_OPT_CB:
      /* Read hdr-opt sent by the passive side */
      return handle_active_parse_hdr(skops, stat);
    case BPF_SOCK_OPS_HDR_OPT_LEN_CB:
      /* Reserve space for writing the header option later in
       * BPF_SOCK_OPS_WRITE_HDR_OPT_CB. */
      return handle_hdr_opt_len(skops, stat);
    case BPF_SOCK_OPS_WRITE_HDR_OPT_CB:
      /* Echo back the server-id as hdr-opt */
      return handle_active_write_hdr_opt(skops, stat);
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
      /* Connection estd: check for server_id */
      return handle_active_estab(skops, stat);
    case BPF_SOCK_OPS_TCP_LISTEN_CB:
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
    default:
      break;
  }
  return SUCCESS;
}

SEC("sockops")
int tcp_pkt_router(struct bpf_sock_ops* skops) {
  __u32 key = GENERIC_STATS_INDEX;
  struct stats* prog_stats;
  struct server_info* s_info;

  prog_stats = bpf_map_lookup_elem(&tpr_stats, &key);
  if (!prog_stats) {
    return CG_ERR;
  }

  __u32 sinfo_key = SERVER_INFO_INDEX;
  s_info = bpf_map_lookup_elem(&server_infos, &sinfo_key);
  if (!s_info) {
    // not much we can do.
    prog_stats->conns_skipped++;
    return CG_OK;
  }
  if (s_info->running_mode == SERVER_MODE) {
    if (handle_passive_cb(skops, prog_stats, s_info)) {
      prog_stats->conns_skipped++;
    }
  } else if (s_info->running_mode == CLIENT_MODE) {
    if (handle_active_cb(skops, prog_stats)) {
      prog_stats->conns_skipped++;
    }
  } else {
    prog_stats->conns_skipped++;
  }
  return CG_OK;
}

// bpf_printk requires GPL license
char _license[] SEC("license") = "Facebook";
int _version SEC("version") = 1;
