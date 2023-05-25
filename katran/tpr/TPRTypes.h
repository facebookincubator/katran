// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <fmt/format.h>
#include <folly/Expected.h>

namespace katran_tpr {

constexpr int kNoFlags = 0;

// For consistency, denote server-mode as 1 and client mode as 0.
constexpr uint8_t kServerMode = 1;
constexpr uint8_t kClientMode = 0;

enum class RunningMode : uint8_t {
  DEFAULT_RESERVED = 0,
  SERVER = 1,
  CLIENT = 2
};

// Information to set in the TCP header option field.
struct tcp_opt {
  uint8_t kind;
  uint8_t len;
  uint32_t server_id;
};

// information about the running mode to pass to the bpf program.
struct server_info {
  RunningMode running_mode;
  // only ipv6 is supported
  uint32_t server_id;
};

// Tentative stats for different transport events
struct tcp_router_stats {
  uint64_t server_id_read{0};
  uint64_t server_id_set{0};
  uint64_t conns_skipped{0};
  uint64_t no_tcp_opt_hdr{0};
  uint64_t error_bad_id{0};
  uint64_t error_write_opt{0};
  uint64_t error_sys_calls{0};
};

// helper methods to constructs useful error message without boiler plate code.
inline folly::Unexpected<std::system_error> makeError(
    int errorCode,
    const std::string& entity,
    const std::string& reason) noexcept {
  const std::string& errorMsg = fmt::format("Failed to {}: {}", entity, reason);
  return folly::makeUnexpected(
      std::system_error(errorCode, std::generic_category(), errorMsg));
}

inline folly::Unexpected<std::system_error> makeError(
    const std::system_error& other,
    const std::string& entity) noexcept {
  const std::string& errorMsg =
      fmt::format("Failed to {}: {}", entity, other.what());
  return folly::makeUnexpected(std::system_error(other.code(), errorMsg));
}

inline bool operator==(RunningMode lhs, RunningMode rhs) {
  return static_cast<std::uint8_t>(lhs) == static_cast<std::uint8_t>(rhs);
}

inline std::ostream& operator<<(std::ostream& os, const RunningMode& mode) {
  switch (mode) {
    case RunningMode::CLIENT:
      os << "CLIENT";
      break;
    case RunningMode::SERVER:
      os << "SERVER";
      break;
    default:
      os << "Unknown running mode.";
  }
  return os;
}

inline std::ostream& operator<<(std::ostream& os, const tcp_router_stats& s) {
  os << "server_id_read=" << s.server_id_read
     << " server_id_set=" << s.server_id_set
     << " conns_skipped=" << s.conns_skipped
     << " no_tcp_opt_hdr=" << s.no_tcp_opt_hdr
     << " error_bad_id=" << s.error_bad_id
     << " error_write_opt=" << s.error_write_opt
     << " error_sys_calls=" << s.error_sys_calls;
  return os;
}

} // namespace katran_tpr
