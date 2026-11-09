#pragma once

#define KDE_PROG_VERSION 1

// Reserved hdr-opt-value for this case.
// Picked random unused value from IANA TCP Option Kind Numbers
#define KDE_CLT_TCP_HDR_OPT_KIND 0xB8 // 184
#define KDE_SRV_TCP_HDR_OPT_KIND 0xB9 // 185

// KDE client options, 3 bytes for KIND, LEN and kde_zone
#define KDE_CLT_TCP_HDR_OPT_LEN 3
// 16 bytes len for the IPv6 in kde_srv_tcp_opt + KIND and LEN
#define KDE_SRV_TCP_HDR_OPT_LEN 18
/* Maintain both lengths, 18b and 20b. Reserve 20b only for clients behind NAT.
 * This helps in saving opt space on the server side.
 * after rollout, client can maintain 4b by default. */
#define KDE_CLT_TCP_HDR_NAT_OPT_LEN 4
#define KDE_SRV_TCP_HDR_NAT_OPT_LEN 20

enum kde_mode {
  DIRECT_ENCAP_MODE_CLIENT = 0,
  DIRECT_ENCAP_MODE_SERVER = 1,
};

enum kde_gue_port : __u16 {
  KDE_GUE_PORT_DEFAULT = 9886,
  KDE_GUE_PORT_KDE = 9887,
};

enum kde_zone : __u8 {
  KDE_ZONE_NONE = 0,
  KDE_ZONE_1 = 1 << 0,
  KDE_ZONE_2 = 1 << 1,
  KDE_ZONE_3 = 1 << 2,
  KDE_ZONE_4 = 1 << 3,
  KDE_ZONE_ALL = 0xFF,
};
#ifdef __cplusplus
inline enum kde_zone operator|(enum kde_zone a, enum kde_zone b) {
  return static_cast<enum kde_zone>(
      static_cast<__u8>(a) | static_cast<__u8>(b));
}
#endif

/* exclusive modes */
enum vip_filter : __u8 {
  KDE_VIP_FILTER_NONE = 0,
  KDE_VIP_FILTER_ALLOWLIST = 1,
  KDE_VIP_FILTER_BLOCKLIST = 2,
};

union kde_ip_address {
  // TODO: support IPv4
  // __be32 daddr;
  __be32 v6addr[4];
};

// Modification to this struct may break version check between diffrent versions
struct kde_bpf_version {
  __u32 version;
  __u8 hash[20];
};

struct encap_sk_info {
  union kde_ip_address direct_ip;
  __u16 encap_port; // used by tc on outer packet
  __be16 nat_sport; // tc rewrites inner sport
  /* used to count number of connections encapped, set once -- first time tc
   encaps. 32-bit so it can be flipped with CAS */
  __u32 encapped;
};

struct kde_stats {
  // common
  __u64 error_sys_calls;
  // client
  __u64 client_opt_set;
  __u64 client_error_write_opt;
  __u64 client_no_kde;
  __u64 client_opt_received;
  __u64 client_sk_stored;
  __u64 client_retrans;
  __u64 client_tuple_store_stale_entries;
  __u64 client_tuple_stored;
  __u64 client_tuple_removed;
  __u64 client_error_tuple_store;
  __u64 client_error_nat_missing;
  // server
  __u64 server_error_write_opt;
  __u64 server_error_setso;
  __u64 server_error_set_cb;
  __u64 server_error_unset_cb;
  __u64 server_error_load_hdr;
  __u64 server_error_reserve;
  __u64 server_error_no_saved_syn;
  __u64 server_error_synack_map_update;
  __u64 server_opt_set;
  __u64 server_nat_opt_set;
  __u64 server_no_kde_syn;
  __u64 server_no_kde;
  __u64 server_rx_zone_v1;
  __u64 server_rx_zone_unknown_acc;
  __u64 server_rx_zone_unknown_rej;
  __u64 server_rx_zone_1_acc;
  __u64 server_rx_zone_1_rej;
  __u64 server_rx_zone_2_acc;
  __u64 server_rx_zone_2_rej;
  __u64 server_rx_zone_3_acc;
  __u64 server_rx_zone_3_rej;
  __u64 server_rx_zone_4_acc;
  __u64 server_rx_zone_4_rej;
  __u64 server_retrans_synack;
  __u64 server_directip_blackhole;
};

struct kde_tc_stats {
  __u64 error_sys_calls;
  __u64 no_sk_store;
  __u64 in_sk_store;
  __u64 no_tuple_store;
  __u64 in_tuple_store;
  __u64 encap_fail;
  __u64 encap_ok;
  __u64 encap_bytes;
  __u64 encap_payload_bytes;
  __u64 error_parse_src;
  __u64 conns_encapped;
  __u64 nat_replace_fail;
};

struct kde_vip {
  union {
    __u32 dst;
    __u32 dstv6[4];
  };
  __u32 dst_port;
};

/// Struct for TCP option sent by client in SYN packet.
// Indicates server that client supports direct encap and which zone client
// is located in.
struct kde_clt_tcp_opt {
  __u8 kind;
  __u8 len;
  __u8 zone;
  __u8 nat_support; // only uses one bit, can be overloaded with flags
} __attribute__((packed));
_Static_assert(
    sizeof(struct kde_clt_tcp_opt) == KDE_CLT_TCP_HDR_NAT_OPT_LEN,
    "opt size mismatch");

// Struct that represents a header options in TCP packet sent by server in
// SYN-ACK packet.
// Includes IP address for client to use for direct encapsulation.
struct kde_srv_tcp_opt {
  __u8 kind;
  __u8 len;
  // TODO: IPv4 support
  __be32 v6addr[4];
  __be16 client_port; // optionally written for clients behind NAT
} __attribute__((packed));
_Static_assert(
    sizeof(struct kde_srv_tcp_opt) == KDE_SRV_TCP_HDR_NAT_OPT_LEN,
    "server tcp opt size mismatch");

struct kde_mac {
  __u8 mac[6];
};

struct tuple {
  __u32 local_ip6[4];
  __u32 remote_ip6[4];
  __u32 local_port;
  __u32 remote_port;
};

enum KDE_LOG_LEVEL {
  KDE_LOG_OFF = 0,
  KDE_LOG_ERROR = 1,
  KDE_LOG_INFO = 2, // per connection logs
  KDE_LOG_DEBUG = 3 // per packet logs
};

struct kde_log_config {
  // Log level for all connections. KDE_SO_LOG logs with values lower or equal
  // to this level will be logged.
  enum KDE_LOG_LEVEL log_level;

  // Log level for filtered connections. KDE_SO_LOGs for connections,
  // that match filter values below and log level lower or equal to this value,
  // will be logged.
  enum KDE_LOG_LEVEL filter_log_level;

  // Log filter match connection by remote port, 0 matches any port.
  // bpf_sock_ops has port as 32 bit value thus __be32 instead of __be16.
  __be32 remote_port;

  // Log filter match connection by remote address, 0 matches any addresses.
  __be32 remote_v6addr[4];

  // Log filter match connection by local port, 0 matches any ports.
  __u32 local_port;
};

#define KDE_LOG_PORT_ANY 0
#define KDE_MAX_VIPS_FILTER 8
