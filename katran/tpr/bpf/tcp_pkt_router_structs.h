// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

struct server_info {
  // 1 == server, 2 == client
  __u8 running_mode;
  // 0 = no, otherwise yes
  __u8 kde_enabled;
  // zones supported by kde
  __u8 kde_zones;
  __u32 server_id;
};

// struct that represents a header options in TCP packet
struct tcp_opt {
  __u8 kind;
  __u8 len;
  __u32 server_id;
} __attribute__((packed));

// struct that represents an option that, if present in the incoming
// syn from the client, indicates that we shouldn't use TPR.
struct kde_clt_tcp_opt_v2 {
  __u8 kind;
  __u8 len;
  __u8 zone;
} __attribute__((packed));
#define KDE_CLT_TCP_HDR_OPT_LEN 2
#define KDE_CLT_TCP_HDR_OPT_V2_LEN 3

// stats for different packet events
struct stats {
  // TODO: these are tentative fields for now
  __u64 server_id_read;
  __u64 server_id_set;
  __u64 conns_skipped;
  __u64 no_tcp_opt_hdr;
  __u64 error_bad_id;
  __u64 error_server_id_zero;
  __u64 error_write_opt;
  __u64 error_sys_calls;
  __u64 ignoring_due_to_kde;
  // stats for the rollout of the new TPR server OPT
  __u64 legacy_server_opt;
  __u64 new_server_opt;
};
