#pragma once

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/vmlinux/vmlinux.h>

#include <katran/kde/bpf/kde_types.h>

extern const volatile struct kde_log_config g_kde_log_config;

static inline const char* sk_op_str(__u32 op) {
  switch (op) {
    case BPF_SOCK_OPS_VOID:
      return "VOID";
    case BPF_SOCK_OPS_TIMEOUT_INIT:
      return "TIMEOUT_INIT";
    case BPF_SOCK_OPS_RWND_INIT:
      return "RWND_INIT";
    case BPF_SOCK_OPS_TCP_CONNECT_CB:
      return "TCP_CONNECT_CB";
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
      return "ACTIVE_ESTABLISHED_CB";
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
      return "PASSIVE_ESTABLISHED_CB";
    case BPF_SOCK_OPS_NEEDS_ECN:
      return "NEEDS_ECN";
    case BPF_SOCK_OPS_BASE_RTT:
      return "BASE_RTT";
    case BPF_SOCK_OPS_RTO_CB:
      return "RTO_CB";
    case BPF_SOCK_OPS_RETRANS_CB:
      return "RETRANS_CB";
    case BPF_SOCK_OPS_STATE_CB:
      return "STATE_CB";
    case BPF_SOCK_OPS_TCP_LISTEN_CB:
      return "TCP_LISTEN_CB";
    case BPF_SOCK_OPS_RTT_CB:
      return "RTT_CB";
    case BPF_SOCK_OPS_PARSE_HDR_OPT_CB:
      return "PARSE_HDR_OPT_CB";
    case BPF_SOCK_OPS_HDR_OPT_LEN_CB:
      return "HDR_OPT_LEN_CB";
    case BPF_SOCK_OPS_WRITE_HDR_OPT_CB:
      return "WRITE_HDR_OPT_CB";
    default:
      return "UNKNOWN";
  }
}

static inline bool kde_should_so_log(
    enum KDE_LOG_LEVEL level,
    struct bpf_sock_ops* skops) {
  if (level <= g_kde_log_config.log_level) {
    return true;
  }

  if (level > g_kde_log_config.filter_log_level) {
    return false;
  }

  if (skops->family != AF_INET6) {
    // Only IPV6 supported for filtered logging
    return false;
  }

  if (g_kde_log_config.remote_port != KDE_LOG_PORT_ANY &&
      skops->remote_port != g_kde_log_config.remote_port) {
    return false;
  }
  if (g_kde_log_config.local_port != KDE_LOG_PORT_ANY &&
      skops->local_port != g_kde_log_config.local_port) {
    return false;
  }

  if (g_kde_log_config.remote_v6addr[0] != 0 &&
      g_kde_log_config.remote_v6addr[1] != 0 &&
      g_kde_log_config.remote_v6addr[2] != 0 &&
      g_kde_log_config.remote_v6addr[3] != 0) {
    if (skops->remote_ip6[0] != g_kde_log_config.remote_v6addr[0] ||
        skops->remote_ip6[1] != g_kde_log_config.remote_v6addr[1] ||
        skops->remote_ip6[2] != g_kde_log_config.remote_v6addr[2] ||
        skops->remote_ip6[3] != g_kde_log_config.remote_v6addr[3]) {
      return false;
    }
  }

  return true;
}

static inline void make_tuple(
    const struct bpf_sock_ops* skops,
    struct tuple* key) {
  *key = (struct tuple){};
  key->local_ip6[0] = skops->local_ip6[0];
  key->local_ip6[1] = skops->local_ip6[1];
  key->local_ip6[2] = skops->local_ip6[2];
  key->local_ip6[3] = skops->local_ip6[3];
  key->remote_ip6[0] = skops->remote_ip6[0];
  key->remote_ip6[1] = skops->remote_ip6[1];
  key->remote_ip6[2] = skops->remote_ip6[2];
  key->remote_ip6[3] = skops->remote_ip6[3];
  key->local_port = bpf_htons(skops->local_port);
  key->remote_port = bpf_htons(bpf_ntohl(skops->remote_port));
}

#define KDE_SO_LOG(level, skops, fmtStr, ...)  \
  ({                                           \
    if (kde_should_so_log(level, skops)) {     \
      bpf_printk(                              \
          "[op=%s rport=%d lport=%d] " fmtStr, \
          sk_op_str(skops->op),                \
          bpf_ntohl(skops->remote_port),       \
          skops->local_port,                   \
          ##__VA_ARGS__);                      \
    }                                          \
  })

#define KDE_SO_LOG_ERROR(skops, fmtStr, ...) \
  KDE_SO_LOG(KDE_LOG_ERROR, skops, fmtStr, ##__VA_ARGS__)
#define KDE_SO_LOG_INFO(skops, fmtStr, ...) \
  KDE_SO_LOG(KDE_LOG_INFO, skops, fmtStr, ##__VA_ARGS__)
#define KDE_SO_LOG_DEBUG(skops, fmtStr, ...) \
  KDE_SO_LOG(KDE_LOG_DEBUG, skops, fmtStr, ##__VA_ARGS__)

// Increment global SO stat for current CPU. Relies on cpu_num being local
// variable.
#define KDE_STAT_INC(stat)     \
  ({                           \
    if (cpu_num < MAX_CPUS) {  \
      g_stats[cpu_num].stat++; \
    }                          \
  })

// Increment global TC stat for current CPU. Relies on cpu_num being local
// variable.
#define KDE_TC_STAT_INC(stat) KDE_TC_STAT_INC_VALUE(stat, 1)

// Increment global TC stat by a value for current CPU.
// Relies on cpu_num being local variable.
#define KDE_TC_STAT_INC_VALUE(stat, val) \
  ({                                     \
    if (cpu_num < MAX_CPUS) {            \
      g_tc_stats[cpu_num].stat += val;   \
    }                                    \
  })
