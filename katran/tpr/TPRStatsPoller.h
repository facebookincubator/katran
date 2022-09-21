// (c) Facebook, Inc. and its affiliates. Confidential and proprietary.

#pragma once

#include <folly/Expected.h>
#include <folly/io/async/AsyncTimeout.h>
#include <folly/io/async/EventBase.h>
#include <katran/tpr/TPRTypes.h>
#include <atomic>
#include <memory>
#include <string>

namespace katran_tpr {

/**
 * Library class to periodically poll stats exported by the tcp_router_stats
 * program. The exported stats are then appended to the fb303-prefix
 */
class TPRStatsPoller : public folly::AsyncTimeout {
 public:
  explicit TPRStatsPoller(
      folly::EventBase* evb,
      int statsMapFd,
      const folly::Optional<std::string>& statsPrefix = folly::none);

  ~TPRStatsPoller() override;

  void timeoutExpired() noexcept override;

  /**
   * Shutdown the Stats Poller. Useful for safe / clean destruction.
   */
  void shutdown();

  /**
   * Start polling for the TPR stats from the bpf program.
   */
  folly::Expected<folly::Unit, std::system_error> runStatsPoller();

  /**
   * Collects aggregated tcp_router_stats over numCpus.
   */
  folly::Expected<tcp_router_stats, std::system_error> collectTPRStats(
      int numCpus);

  /**
   * Returns number of cpus in the host.
   * (Public for unit tests)
   */
  static folly::Expected<int, std::system_error> getCpuCount();

 private:
  /**
   * helper functiom to periodically update fb303 stats
   */
  void updateStatsPeriodically();

  /**
   * event base to run periodic tasks
   */
  folly::EventBase* evb_;

  /**
   * Optional prefix for the fb303 counter
   */
  std::string statsPrefix_ = "";

  /**
   * FD of the bpf map containing per-cpu stats
   */
  int statsMapFd_{-1};

  /**
   * Number of available cpus in the host. It is used to aggregate per-cpu
   * counters in the bpf map.
   */
  int numCpus_{0};
  /** flag to indicate that the server is in the shutdown phase
   * this is to make sure that we do not schedule events such as ones to start
   * taking traffic if this service moves to the shutdown / draining phase
   */
  std::atomic<bool> shutdown_{false};
};

} // namespace katran_tpr
