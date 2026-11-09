#pragma once

#include <bpf/bpf_helpers.h>
#include <bpf/vmlinux/vmlinux.h>
#include <katran/kde/bpf/kde_constants.h>
#include <katran/kde/bpf/kde_maps.h>
#include <katran/kde/bpf/kde_types.h>
#include <katran/kde/bpf/kde_utils.h>

extern struct kde_stats g_stats[MAX_CPUS];

const volatile bool g_enable_for_all_vips = false;

const volatile __u8 g_kde_client_zone = 0;

const volatile __u16 g_kde_encap_port = KDE_GUE_PORT_DEFAULT;

/* host mode: one instance serves all containers on the host and tc runs on
   the host NIC egress. By then the host has forwarded the packet and
   cleared skb->sk, so the socket's storage is unreachable from tc. Store
   the direct IP in a map keyed by the connection tuple instead. */
const volatile __u8 g_kde_client_host_mode = 0;
/* nat mode: when clients sit behind a NAT -- NATs only rewrite the
 * outer packet while inner stays untouched. This leads SYN (unencapped) and
 * ACK+(encapped) packets on different ports even tho they belong to the same
 * connection. With NAT mode, client asks server to echo observered port on
 * SYN-ACK. KDE will then rewrite inner on all encapped packets to match NAT */
const volatile bool g_kde_client_nat_mode = false;

// TODO: remove this helper if it is unused.
static inline bool is_kde_enabled_on_vip(struct bpf_sock_ops* skops) {
  if (g_enable_for_all_vips) {
    return true;
  }

  if (skops->family != AF_INET6) {
    // We may change this later on if we decide to enable it for ipv4
    return false;
  }

  struct kde_vip vip = {};

  vip.dstv6[0] = skops->remote_ip6[0];
  vip.dstv6[1] = skops->remote_ip6[1];
  vip.dstv6[2] = skops->remote_ip6[2];
  vip.dstv6[3] = skops->remote_ip6[3];

  vip.dst_port = skops->remote_port;

  if (!bpf_map_lookup_elem(&kde_vip_map, &vip)) {
    return false;
  }

  return true;
}

static inline int clt_handle_tcp_listen(
    struct bpf_sock_ops* skops,
    __u32 cpu_num) {
  int flags = skops->bpf_sock_ops_cb_flags |
      BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG |
      BPF_SOCK_OPS_PARSE_UNKNOWN_HDR_OPT_CB_FLAG;
  int err = bpf_sock_ops_cb_flags_set(skops, flags);
  if (err) {
    KDE_STAT_INC(error_sys_calls);
    KDE_SO_LOG_ERROR(skops, "Error setting callback flags with error %d", err);
    return CG_ERR;
  }
  KDE_SO_LOG_INFO(skops, "Set callback flags 0x%x", flags);
  return CG_OK;
}

static inline int clt_handle_hdr_opt_len(
    struct bpf_sock_ops* skops,
    __u32 cpu_num) {
  if ((skops->skb_tcp_flags & TCPHDR_SYN) != TCPHDR_SYN) {
    KDE_SO_LOG_DEBUG(skops, "hdr_opt_len non-SYN packet");
    return CG_OK;
  }
  if (!is_kde_enabled_on_vip(skops)) {
    KDE_SO_LOG_DEBUG(skops, "hdr_opt_len KDE not enabled on vip");
    return CG_OK;
  }
  int reserve_opt_len = KDE_CLT_TCP_HDR_OPT_LEN;
  if (g_kde_client_nat_mode) {
    reserve_opt_len = KDE_CLT_TCP_HDR_NAT_OPT_LEN;
  }
  int err = bpf_reserve_hdr_opt(skops, reserve_opt_len, 0);
  if (err) {
    KDE_STAT_INC(error_sys_calls);
    KDE_SO_LOG_ERROR(
        skops,
        "Failed reserve header size %d with error %d",
        KDE_CLT_TCP_HDR_OPT_LEN,
        err);
    return CG_ERR;
  }
  KDE_SO_LOG_INFO(skops, "Reserved header len %d", reserve_opt_len);
  return CG_OK;
}

static inline int ctl_write_hdr_opt(struct bpf_sock_ops* skops, __u32 cpu_num) {
  if ((skops->skb_tcp_flags & TCPHDR_SYN) != TCPHDR_SYN) {
    KDE_SO_LOG_DEBUG(skops, "write_hdr_opt non-SYN packet");
    return CG_OK;
  }
  if (!is_kde_enabled_on_vip(skops)) {
    KDE_SO_LOG_DEBUG(skops, "write_hdr_opt KDE not enabled on vip");
    return CG_OK;
  }

  struct kde_clt_tcp_opt hdr_opt = {};
  __u8 opt_len = KDE_CLT_TCP_HDR_OPT_LEN;
  hdr_opt.kind = KDE_CLT_TCP_HDR_OPT_KIND;
  hdr_opt.zone = g_kde_client_zone;
  if (g_kde_client_nat_mode) {
    hdr_opt.nat_support = 1;
    opt_len = KDE_CLT_TCP_HDR_NAT_OPT_LEN;
  } // NAT MODE
  hdr_opt.len = opt_len;
  int err = bpf_store_hdr_opt(skops, &hdr_opt, opt_len, NO_FLAGS);
  if (err) {
    KDE_STAT_INC(client_error_write_opt);
    KDE_SO_LOG_ERROR(skops, "Failed write header with %d", err);
    return CG_ERR;
  }

  KDE_STAT_INC(client_opt_set);
  KDE_SO_LOG_INFO(
      skops, "Wrote header with values 0x%x 0x%x", hdr_opt.kind, hdr_opt.len);
  return CG_OK;
}

static inline int ctl_store_direct_ip(
    struct bpf_sock_ops* skops,
    struct bpf_sock* sk,
    const struct kde_srv_tcp_opt* kde_opt,
    __u32 cpu_num) {
  struct encap_sk_info ei = {};
  ei.direct_ip.v6addr[0] = kde_opt->v6addr[0];
  ei.direct_ip.v6addr[1] = kde_opt->v6addr[1];
  ei.direct_ip.v6addr[2] = kde_opt->v6addr[2];
  ei.direct_ip.v6addr[3] = kde_opt->v6addr[3];
  ei.encap_port = g_kde_encap_port;
  if (g_kde_client_nat_mode) {
    ei.nat_sport = kde_opt->client_port;
  }

  __u32 cb_flags = skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_RETRANS_CB_FLAG;
  if (g_kde_client_host_mode) {
    // the state callback deletes the tuple map entry on close
    cb_flags |= BPF_SOCK_OPS_STATE_CB_FLAG;
  }
  int err = bpf_sock_ops_cb_flags_set(skops, cb_flags);
  if (err) {
    KDE_STAT_INC(error_sys_calls);
    return CG_ERR;
  }

  // handle_retrans today uses sk storage, so continue to write it even in host
  // mode until we decide on a longer term design for host mode
  struct encap_sk_info* eiPtr = bpf_sk_storage_get(
      &katran_de_sk_store, sk, &ei, BPF_SK_STORAGE_GET_F_CREATE);
  if (!eiPtr) {
    KDE_STAT_INC(error_sys_calls);
    return CG_OK;
  }
  KDE_STAT_INC(client_sk_stored);

  if (g_kde_client_host_mode) {
    struct tuple key = {};
    make_tuple(skops, &key);
    err = bpf_map_update_elem(&katran_de_tuple_store, &key, &ei, BPF_NOEXIST);
    if (!err) {
      KDE_STAT_INC(client_tuple_stored);
    } else if (err == -EEXIST) {
      // tuple reused before its old entry was removed
      KDE_STAT_INC(client_tuple_store_stale_entries);
      err = bpf_map_update_elem(&katran_de_tuple_store, &key, &ei, BPF_ANY);
    }
    if (err) { // E2BIG (map full) or ENOMEM
      KDE_STAT_INC(client_error_tuple_store);
    }
  }
  return CG_OK;
}

static inline int ctl_active_estab(struct bpf_sock_ops* skops, __u32 cpu_num) {
  if ((skops->skb_tcp_flags & TCPHDR_SYNACK) != TCPHDR_SYNACK) {
    return CG_OK;
  }
  struct bpf_sock* sk = skops->sk;
  if (!sk) {
    return CG_OK;
  }

  struct kde_srv_tcp_opt kde_opt = {};
  kde_opt.kind = KDE_SRV_TCP_HDR_OPT_KIND;
  int ret = bpf_load_hdr_opt(skops, &kde_opt, sizeof(kde_opt), 0);
  /* during rollout, accept both: old server send 18B, new server send 20B
   * when NAT is requested */
  if (ret == KDE_SRV_TCP_HDR_OPT_LEN || ret == KDE_SRV_TCP_HDR_NAT_OPT_LEN) {
    KDE_STAT_INC(client_opt_received);
    if (g_kde_client_nat_mode && ret == KDE_SRV_TCP_HDR_OPT_LEN) {
      KDE_STAT_INC(client_error_nat_missing);
    }
    return ctl_store_direct_ip(skops, sk, &kde_opt, cpu_num);
  } else if (ret == -ENOMSG) {
    KDE_STAT_INC(client_no_kde);
    return CG_OK;
  } else {
    KDE_STAT_INC(error_sys_calls);
    return CG_OK;
  }
}

static inline int clt_handle_retrans(
    struct bpf_sock_ops* skops,
    __u32 cpu_num) {
  struct bpf_sock* sk = skops->sk;
  if (!sk) {
    return CG_OK;
  }
  // Socket has DE enabled, do the socket storage lookup to update retransmit
  // info
  struct encap_sk_info* ei =
      bpf_sk_storage_get(&katran_de_sk_store, sk, NULL, NO_FLAGS);
  if (ei) {
    // Update statistics for DE sockets only
    KDE_STAT_INC(client_retrans);
  }
  return CG_OK;
}

static inline int clt_handle_state_change(
    struct bpf_sock_ops* skops,
    __u32 cpu_num) {
  if (skops->args[1] != BPF_TCP_CLOSE) {
    return CG_OK;
  }
  if (!g_kde_client_host_mode) {
    return CG_OK;
  }
  struct tuple key = {};
  make_tuple(skops, &key);
  int err = bpf_map_delete_elem(&katran_de_tuple_store, &key);
  if (!err) {
    KDE_STAT_INC(client_tuple_removed);
  } else if (err != -ENOENT) {
    KDE_STAT_INC(client_error_tuple_store);
  }
  return CG_OK;
}

static inline int handle_client(struct bpf_sock_ops* skops, __u32 cpu_num) {
  KDE_SO_LOG_DEBUG(skops, "handle_client");
  switch (skops->op) {
    case BPF_SOCK_OPS_TCP_CONNECT_CB:
      return clt_handle_tcp_listen(skops, cpu_num);
    case BPF_SOCK_OPS_HDR_OPT_LEN_CB:
      // Reserve space for writing the header option later in
      // BPF_SOCK_OPS_WRITE_HDR_OPT_CB.
      return clt_handle_hdr_opt_len(skops, cpu_num);
    case BPF_SOCK_OPS_WRITE_HDR_OPT_CB:
      // Send hdr-opt with indication of DE support
      return ctl_write_hdr_opt(skops, cpu_num);
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
      // Connection estd: check for DE IP
      return ctl_active_estab(skops, cpu_num);
    case BPF_SOCK_OPS_RETRANS_CB:
      // Retransmission detected
      return clt_handle_retrans(skops, cpu_num);
    case BPF_SOCK_OPS_STATE_CB:
      return clt_handle_state_change(skops, cpu_num);
    default:
      return CG_OK;
  }
}
