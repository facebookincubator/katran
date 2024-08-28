// Copyright (c) Meta Platforms, Inc. and affiliates.

#include <folly/io/async/EventBaseManager.h>
#include <memory>

#include <katran/tpr/TPRTypes.h>
#include <katran/tpr/TcpPktRouter.h>
#include <katran/tpr/bpf_util/BpfUtil.h>

namespace katran_tpr {

// max 24-bit value
constexpr uint32_t kMaxServerId = (1 << 24) - 1;
constexpr uint32_t kServerInfoIndex = 0;
const std::string kServerInfoMap = "server_infos";

TcpPktRouter::TcpPktRouter(
    RunningMode mode,
    const std::string& cgroupPath,
    bool kdeEnabled,
    std::optional<uint32_t> serverPort)
    : mode_(mode),
      cgroupPath_(cgroupPath),
      kdeEnabled_(kdeEnabled),
      serverPort_(serverPort),
      skel_(BpfSkeleton<tpr_bpf>::make()) {}

TcpPktRouter::~TcpPktRouter() {
  shutdown();
}

folly::Expected<folly::Unit, std::system_error> TcpPktRouter::init(
    bool pollStats) {
  CHECK(!isInitialized_);
  auto res = BpfUtil::init();
  if (res.hasError()) {
    return makeError(res.error(), __func__);
  }
  res = skel_.open();
  if (!res) {
    LOG(ERROR) << "Failed to open Katran TPR prog: " << res.error().what();
    return makeError(res.error(), __func__);
  }

  if (serverPort_.has_value()) {
    skel_->rodata->g_server_exclusive_port = serverPort_.value();
    LOG(INFO) << "TPR restricted to port " << serverPort_.value();
  }

  res = skel_.load();
  if (!res) {
    LOG(ERROR) << "Failed to load Katran TPR prog: " << res.error().what();
    return makeError(res.error(), __func__);
  }
  progFd_ = bpf_program__fd(skel_->progs.tcp_pkt_router);
  if (progFd_ < 0) {
    return makeError(
        std::system_error(std::error_code(), "Invalid prog FD"), __func__);
  }
  res = BpfUtil::attachCgroupProg(progFd_, cgroupPath_, BPF_F_ALLOW_MULTI);
  if (res.hasError()) {
    return makeError(res.error(), __func__);
  }
  auto updateRes = updateServerInfo();
  if (updateRes.hasError()) {
    return makeError(updateRes.error(), __func__);
  }
  isInitialized_ = true;
  if (pollStats) {
    int statsMapFd = bpf_map__fd(skel_->maps.tpr_stats);
    if (statsMapFd < 0) {
      LOG(ERROR) << "Cannot find bpf map tpr_stats; shutting downn TPR";
      // Try to be graceful even if it can't find that stats map
      return shutdown();
    }
    statsPoller_ = createStatsPoller(
        folly::EventBaseManager::get()->getEventBase(), statsMapFd);
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
  if (statsPoller_) {
    statsPoller_->shutdown();
  }
  auto res = BpfUtil::detachCgroupProg(progFd_, cgroupPath_);
  if (res.hasError()) {
    LOG(ERROR) << res.error().what();
    return makeError(res.error(), __func__);
  }
  isInitialized_ = false;
  return folly::Unit();
}

bool TcpPktRouter::setServerIdV6(uint32_t id) {
  CHECK_EQ(mode_, RunningMode::SERVER);
  if (id == 0) {
    return false;
  }
  if (id > kMaxServerId) {
    return false;
  }
  v6Id_ = id;
  if (isInitialized_) {
    updateServerInfo();
  }
  return true;
}

folly::Expected<folly::Unit, std::system_error>
TcpPktRouter::updateServerInfo() noexcept {
  struct server_info info = {};
  if (mode_ == RunningMode::SERVER) {
    info.running_mode = RunningMode::SERVER;
    info.kde_enabled = kdeEnabled_;
    info.server_id = v6Id_;
    if (info.server_id == 0) {
      LOG(ERROR) << "TCP Pkt router is set but server_id is 0. Please check "
                    "if the id has been set properly.";
    }
  } else {
    info.running_mode = RunningMode::CLIENT;
    info.server_id = 0;
  }
  int mapFd = bpf_map__fd(skel_->maps.server_infos);
  auto updateRes = BpfUtil::updateMapElement(mapFd, kServerInfoIndex, info);
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
  if (!isInitialized_) {
    return makeError(EINVAL, __func__, "BPF program is not yet loaded.");
  }
  return progFd_;
}

folly::Expected<uint32_t, std::system_error>
TcpPktRouter::getServerIdFromSkSidStoreMap(int socketFd) noexcept {
  int skSidStoreMapFd = bpf_map__fd(skel_->maps.sk_sid_store);
  uint32_t serverId = 0;
  auto lookRes = BpfUtil::lookupMapElement(skSidStoreMapFd, socketFd, serverId);
  if (lookRes.hasError()) {
    return makeError(lookRes.error(), __func__);
  }
  return serverId;
}

} // namespace katran_tpr
