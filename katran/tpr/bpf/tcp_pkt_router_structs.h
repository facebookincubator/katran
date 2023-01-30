// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

struct server_info {
  // 1 == server, 2 == client
  __u8 running_mode;
  __u32 server_id;
};

// struct that represents a header options in TCP packet
struct tcp_opt {
  __u8 kind;
  __u8 len;
  __u32 server_id;
} __attribute__((packed));

// stats for different packet events
struct stats {
  // TODO: these are tentative fields for now
  __u64 server_id_read;
  __u64 server_id_set;
  __u64 conns_skipped;
  __u64 no_tcp_opt_hdr;
  __u64 error_bad_id;
  __u64 error_write_opt;
  __u64 error_sys_calls;
};
