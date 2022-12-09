// (c) Facebook, Inc. and its affiliates. Confidential and proprietary.

#pragma once

#include <folly/Expected.h>
#include <glog/logging.h>
#include <memory>
#include <string>
#include <vector>

#include <katran/tpr/TPRStatsPoller.h>
#include <katran/tpr/TPRTypes.h>
#include <katran/tpr/TprBpfAdapter.h>

namespace katran_tpr {

class TcpPktRouter {
 public:
  explicit TcpPktRouter(RunningMode mode, const std::string& cgroupPath);

  virtual ~TcpPktRouter();

  /**
   * Instantiates TcpPktRouter including attaching of sockops
   * bpf program to the containers cgroup.
   * @param bool pollStats if true invokes TPRStatsPoller
   * Returns folly::Unit() if successful else system_error
   */
  folly::Expected<folly::Unit, std::system_error> init(bool pollStats = false);

  /**
   * Gracefully detach and unload the sockops bpf program from cgroupPath_
   * Returns folly::Unit() if successful else system_error
   */
  folly::Expected<folly::Unit, std::system_error> shutdown();

  /**
   * Returns true iff init() is successful
   */
  bool isInitialized() const noexcept {
    return isInitialized_;
  }

  /**
   * Set IPv6 server_id for this server.
   * This is applicable only in *Origin*. It shares that same server-id as
   * the one used for QUIC.
   * Note: only IPv6 is supported.
   * Returns true if the id is set successfully.
   */
  bool setServerIdV6(uint32_t id);

  /**
   * Get IPv6 server_id for this server.
   * This is applicable only in *Origin*. It shares that same server-id as
   * the one used for QUIC.
   * Note: only IPv6 is supported.
   */
  uint32_t getServerIdV6() const noexcept {
    return v6Id_;
  }

  /**
   * Collects aggregated tcp_router_stats over numCpus.
   */
  folly::Expected<tcp_router_stats, std::system_error> collectTPRStats();

 protected:
  virtual std::unique_ptr<TPRStatsPoller> createStatsPoller(
      folly::EventBase* evb,
      int statsMapFd);

  RunningMode mode_;

 private:
  folly::Expected<folly::Unit, std::system_error> updateServerInfo() noexcept;

  bool isInitialized_{false};
  uint32_t v6Id_;
  std::string cgroupPath_;
  TprBpfAdapter adapter_;
  /**
   * Polls stats for packet level events periodically, and
   * publishes fb303 counters
   */
  std::unique_ptr<TPRStatsPoller> statsPoller_;
};

} // namespace katran_tpr
