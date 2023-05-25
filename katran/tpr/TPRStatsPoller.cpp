// Copyright (c) Meta Platforms, Inc. and affiliates.

#include <katran/tpr/TPRStatsPoller.h>

#include <fmt/format.h>
#include <folly/FileUtil.h>
#include <folly/String.h>

extern "C" {
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
}

namespace katran_tpr {

namespace {
constexpr int kError = -1;
constexpr int kMaxIndex = 1;
constexpr int kMinIndex = 0;
constexpr int kTenSecondsInMs = 10000; // sec in msec
constexpr static folly::StringPiece kPossibleCpusFile(
    "/sys/devices/system/cpu/possible");
} // namespace

void TPRStatsPoller::incrementCounter(const std::string& name) {
  VLOG(5) << "Incremented counter " << name;
}

void TPRStatsPoller::setCounter(const std::string& name, int64_t val) {
  VLOG(5) << "Set counter " << name << " to " << val;
}

void TPRStatsPoller::setStatsCounters(const tcp_router_stats& stats) {
  setCounter("server_id_read", stats.server_id_read);
  setCounter("server_id_set", stats.server_id_set);
  setCounter("conns_skipped", stats.conns_skipped);
  setCounter("no_tcp_opt_hdr", stats.no_tcp_opt_hdr);
  setCounter("error_bad_id", stats.error_bad_id);
  setCounter("error_write_opt", stats.error_write_opt);
  setCounter("error_sys_calls", stats.error_sys_calls);
}

TPRStatsPoller::TPRStatsPoller(
    RunningMode mode,
    folly::EventBase* evb,
    int statsMapFd)
    : AsyncTimeout(evb), mode_(mode), evb_(evb), statsMapFd_(statsMapFd) {}

TPRStatsPoller::~TPRStatsPoller() {
  shutdown();
}

void TPRStatsPoller::shutdown() {
  if (shutdown_) {
    return;
  }
  shutdown_ = true;
  if (statsMapFd_ >= 0) {
    ::close(statsMapFd_);
  }
  evb_->runImmediatelyOrRunInEventBaseThreadAndWait(
      [this]() { cancelTimeout(); });
  VLOG(2) << "TPR Stats poller is shutting down..";
}

folly::Expected<folly::Unit, std::system_error>
TPRStatsPoller::runStatsPoller() {
  // some bpf check
  auto maybeNumCpus = getCpuCount();
  if (maybeNumCpus.hasError()) {
    return makeError(maybeNumCpus.error(), __func__);
  }
  numCpus_ = maybeNumCpus.value();

  if (statsMapFd_ < 0) {
    return makeError(
        EINVAL, __func__, fmt::format("Invalid map-fd found: {}", statsMapFd_));
  }
  updateStatsPeriodically();
  evb_->runImmediatelyOrRunInEventBaseThreadAndWait(
      [this]() { scheduleTimeout(kTenSecondsInMs); });
  VLOG(2) << "TPR Stats poller successfully initialized and is running";
  return folly::Unit();
}

void TPRStatsPoller::updateStatsPeriodically() {
  // to handle a case where shutdown started while this fn is scheduled
  if (shutdown_) {
    return;
  }
  std::string modeStr = (mode_ == RunningMode::SERVER ? "server" : "client");
  setCounter("mode." + modeStr, 1);

  incrementCounter("periodic_stats_update");
  auto stats = collectTPRStats(numCpus_);
  if (stats.hasError()) {
    LOG(ERROR) << "error while polling tcp_router_stats stats: "
               << stats.error().what();
    return;
  }
  setStatsCounters(*stats);
}

void TPRStatsPoller::timeoutExpired() noexcept {
  if (shutdown_) {
    return;
  }
  updateStatsPeriodically();
  scheduleTimeout(kTenSecondsInMs);
}

folly::Expected<tcp_router_stats, std::system_error>
TPRStatsPoller::collectTPRStats(int numCpus) {
  struct tcp_router_stats aggregateStats = {};
  uint32_t key = 0;

  if (statsMapFd_ < 0) {
    return makeError(
        EINVAL,
        __func__,
        fmt::format(
            "Trying to get stats but the statsMapFd is not valid: "
            "{}. Did you initialize it?",
            statsMapFd_));
  }
  if (numCpus < 0) {
    return makeError(
        EINVAL,
        __func__,
        fmt::format(
            "Invalid numCpus provided: "
            "{}. Did you call getCpuCount()?",
            numCpus));
  }

  struct tcp_router_stats percpu_stats[numCpus];

  if (bpf_map_lookup_elem(statsMapFd_, &key, &percpu_stats)) {
    int savedErrno = errno;
    return makeError(
        savedErrno,
        __func__,
        fmt::format(
            "Error while looking up stats in map-fd: {}, errno: {}",
            statsMapFd_,
            folly::errnoStr(savedErrno)));
  }
  for (auto& stat : percpu_stats) {
    aggregateStats.server_id_read += stat.server_id_read;
    aggregateStats.server_id_set += stat.server_id_set;
    aggregateStats.conns_skipped += stat.conns_skipped;
    aggregateStats.no_tcp_opt_hdr += stat.no_tcp_opt_hdr;
    aggregateStats.error_bad_id += stat.error_bad_id;
    aggregateStats.error_write_opt += stat.error_write_opt;
    aggregateStats.error_sys_calls += stat.error_sys_calls;
  }
  return aggregateStats;
}

folly::Expected<int, std::system_error> TPRStatsPoller::getCpuCount() {
  std::string cpus;
  auto res = folly::readFile(kPossibleCpusFile.data(), cpus);
  if (!res) {
    return makeError(
        EINVAL,
        __func__,
        fmt::format("Can't read number of cpus from: {}", kPossibleCpusFile));
  }
  VLOG(3) << "cpus file " << kPossibleCpusFile << " content: " << cpus;
  // Examples of what we expect the contents of the file to look like:
  // "0-79": This means that there are 80 cpus
  // "0": This means that there is 1 cpu
  // "0-24": This means that there are 25 cpus
  std::vector<uint32_t> range;
  folly::split('-', cpus, range);
  if (range.size() == 2) {
    return range[kMinIndex] == 0 ? range[kMaxIndex] + 1 : kError;
  } else if (range.size() == 1) {
    // if system contains just a single cpu content of the file would be just
    // "0"
    return 1;
  } else {
    return makeError(
        EBADF,
        __func__,
        fmt::format(
            "unsupported format of file: {}, format: {}",
            kPossibleCpusFile,
            cpus));
  }
}

} // namespace katran_tpr
