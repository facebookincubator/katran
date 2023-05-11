// Copyright (c) Meta Platforms, Inc. and affiliates.

#include <folly/io/async/EventBaseManager.h>
#include <memory>

#include <katran/tpr/TPRTypes.h>
#include <katran/tpr/TcpPktRouter.h>
#include <katran/tpr/bpf_util/BpfSkeleton.h>

#ifdef KATRAN_CMAKE_BUILD
#include "tpr_bpf.skel.h" // @manual
#else
#include <katran/tpr/bpf/tpr_bpf.skel.h>
#endif

namespace katran_tpr {

// max 24-bit value
constexpr uint32_t kMaxServerId = (1 << 24) - 1;
constexpr uint32_t kServerInfoIndex = 0;
const std::string kServerInfoMap = "server_infos";

TcpPktRouter::TcpPktRouter(RunningMode mode, const std::string& cgroupPath)
    : mode_(mode), cgroupPath_(cgroupPath) {}

TcpPktRouter::~TcpPktRouter() {
  shutdown();
}

folly::Expected<folly::Unit, std::system_error> TcpPktRouter::init(
    bool pollStats) {
  CHECK(!isInitialized_);
  auto res = adapter_.setRLimit();
  if (res.hasError()) {
    return makeError(res.error(), __func__);
  }
  auto buf = BpfSkeleton<tpr_bpf>::elfBytes();
  res = adapter_.loadFromBuffer((char*)buf.data(), buf.size());
  if (res.hasError()) {
    return makeError(res.error(), __func__);
  }
  auto mayBeFd = adapter_.getBpfProgramFd();
  if (mayBeFd.hasError()) {
    return makeError(mayBeFd.error(), __func__);
  }
  res = adapter_.attachCgroupProg(
      mayBeFd.value(), cgroupPath_, BPF_F_ALLOW_MULTI);
  if (res.hasError()) {
    return makeError(res.error(), __func__);
  }
  auto updateRes = updateServerInfo();
  if (updateRes.hasError()) {
    return makeError(updateRes.error(), __func__);
  }
  isInitialized_ = true;
  if (pollStats) {
    auto mayBeStatsFd = adapter_.getMapFdByName("tpr_stats");
    if (mayBeStatsFd.hasError()) {
      LOG(ERROR) << "Cannot find bpf map tpr_stats; shutting downn TPR, error="
                 << mayBeStatsFd.error().what();
      // Try to be graceful even if it can't find that stats map
      return shutdown();
    }
    statsPoller_ = createStatsPoller(
        folly::EventBaseManager::get()->getEventBase(), mayBeStatsFd.value());
    auto statsRes = statsPoller_->runStatsPoller();
    if (statsRes.hasError()) {
      LOG(ERROR) << "Error while initializing statsPoller; error="
                 << statsRes.error().what();
    }
  }
  LOG(INFO) << "TcpPktRouter is initilized successfully in "
            << (mode_ == RunningMode::SERVER ? "server" : "client") << " mode";

  // TODO once the attach is successful, look for already attached instances
  // of tcp_pkt_router sockops (e.g. from Proxygen that crashed) and
  // delete the ones not belonging to this process.
  return folly::Unit();
}

folly::Expected<folly::Unit, std::system_error> TcpPktRouter::shutdown() {
  if (!isInitialized_) {
    return folly::Unit();
  }
  if (adapter_.getBpfState() == TprBpfAdapter::BpfState::INIT) {
    // there's nth to cleanup since the bpf prog isn't loaded
    isInitialized_ = false;
    return folly::Unit();
  }
  if (statsPoller_) {
    statsPoller_->shutdown();
  }
  auto mayBeProgFd = adapter_.getBpfProgramFd();
  if (mayBeProgFd.hasError()) {
    return makeError(mayBeProgFd.error(), __func__);
  }
  auto res = adapter_.detachCgroupProg(mayBeProgFd.value(), cgroupPath_);
  if (res.hasError()) {
    LOG(ERROR) << res.error().what();
    return makeError(res.error(), __func__);
  }
  res = adapter_.unload();
  if (res.hasError()) {
    LOG(ERROR) << res.error().what();
    return makeError(res.error(), __func__);
  }
  isInitialized_ = false;
  return folly::Unit();
}

bool TcpPktRouter::setServerIdV6(uint32_t id) {
  CHECK(!isInitialized_);
  CHECK_EQ(mode_, RunningMode::SERVER);
  if (id == 0) {
    return false;
  }
  if (id > kMaxServerId) {
    return false;
  }
  v6Id_ = id;
  return true;
}

folly::Expected<folly::Unit, std::system_error>
TcpPktRouter::updateServerInfo() noexcept {
  struct server_info info = {};
  if (mode_ == RunningMode::SERVER) {
    info.running_mode = RunningMode::SERVER;
    info.server_id = v6Id_;
    if (info.server_id == 0) {
      LOG(ERROR) << "TCP Pkt router is set but server_id is 0. Please check "
                    "if the id has been set properly.";
    }
  } else {
    info.running_mode = RunningMode::CLIENT;
    info.server_id = 0;
  }
  auto mayBeMapFd = adapter_.getMapFdByName(kServerInfoMap);
  if (mayBeMapFd.hasError()) {
    return makeError(mayBeMapFd.error(), __func__);
  }
  auto updateRes =
      adapter_.updateMapElement(mayBeMapFd.value(), kServerInfoIndex, info);
  if (updateRes.hasError()) {
    return makeError(updateRes.error(), __func__);
  }
  LOG(INFO) << "set server_id=" << info.server_id;
  return folly::Unit();
}

folly::Expected<tcp_router_stats, std::system_error>
TcpPktRouter::collectTPRStats() {
  if (!isInitialized_) {
    return makeError(ENOENT, __func__, "TPR is not initialized");
  }
  if (!statsPoller_) {
    return makeError(
        ENOENT, __func__, " Stats poller in TPR is not initialized");
  }
  auto maybeCpus = TPRStatsPoller::getCpuCount();
  if (maybeCpus.hasError()) {
    return makeError(maybeCpus.error(), __func__);
  }
  return statsPoller_->collectTPRStats(maybeCpus.value());
}

std::unique_ptr<TPRStatsPoller> TcpPktRouter::createStatsPoller(
    folly::EventBase* evb,
    int statsMapFd) {
  return std::make_unique<TPRStatsPoller>(mode_, evb, statsMapFd);
}

folly::Expected<int, std::system_error>
TcpPktRouter::getBpfProgramFd() noexcept {
  return adapter_.getBpfProgramFd();
}

} // namespace katran_tpr
