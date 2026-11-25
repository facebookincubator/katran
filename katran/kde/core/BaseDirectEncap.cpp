#include <katran/kde/core/BaseDirectEncap.h>

#include <fcntl.h>
#include <glog/logging.h>
#include <net/if.h>
#include <string>
#include "fb303/ServiceData.h"

#include <folly/ScopeGuard.h>
#include <folly/String.h>
#include <katran/kde/consts.h>
#include "katran/kde/core/KdeBpfUtil.h"

namespace katran_tpr {

BaseDirectEncap::BaseDirectEncap(
    const std::string& iface,
    decltype(oss_kde_zones)& zoneMap,
    bool set_limits)
    : adapter_(set_limits),
      soSkel_(BpfSkeleton<katran_de_so_bpf>::make()),
      iface_(iface),
      zoneMap_(zoneMap) {
  setLogConfig(
      KDE_LOG_OFF,
      KDE_LOG_OFF,
      KDE_LOG_PORT_ANY,
      KDE_LOG_PORT_ANY,
      std::nullopt);
}

BaseDirectEncap::~BaseDirectEncap() {}

void BaseDirectEncap::setCgroupPath(const std::string& cgroupPath) {
  cgroupPath_ = cgroupPath;
}

void BaseDirectEncap::setPin(bool pin) {
  this->pin_ = pin;
}

void BaseDirectEncap::setLogConfig(
    KDE_LOG_LEVEL level,
    KDE_LOG_LEVEL filterLevel,
    uint16_t localPort,
    uint16_t remotePort,
    std::optional<folly::IPAddress> remoteAddr) {
  logLevel_ = level;
  filterLogLevel_ = filterLevel;
  logLocalPort_ = localPort;
  logRemotePort_ = remotePort;
  if (remoteAddr.has_value()) {
    CHECK(remoteAddr->isV6()) << "Remote address must be IPv6";
    logRemoteAddr_ = *remoteAddr;
  } else {
    logRemoteAddr_ = folly::IPAddress::tryFromString("0::0").value();
  }
}

folly::Expected<folly::Unit, std::system_error> BaseDirectEncap::loadSockOps() {
  if (cgroupPath_.empty()) {
    LOG(ERROR) << "Cgroup path must be set";
    return folly::makeUnexpected(
        std::system_error(
            EINVAL, std::generic_category(), "Cgroup path must be set"));
  }

  cgroupFd_ = ::open(cgroupPath_.c_str(), O_DIRECTORY, O_RDONLY);
  if (cgroupFd_ < 0) {
    LOG(ERROR) << "Failed to open cgroup " << cgroupPath_;
    return folly::makeUnexpected(
        std::system_error(
            errno, std::generic_category(), "Failed to open cgroup"));
  }

  auto res = soSkel_.open();
  if (!res) {
    LOG(ERROR) << "Failed to open Katran DirectEncap SockOps prog: "
               << res.error().what();
    return folly::makeUnexpected(res.error());
  }

  setLogSockopsVars();
  auto setSockopsVarsResult = setSockopsVars();
  if (setSockopsVarsResult.hasError()) {
    return folly::makeUnexpected(setSockopsVarsResult.error());
  }

  res = soSkel_.load();
  if (!res) {
    LOG(ERROR) << "Failed to load Katran DirectEncap SockOps prog: "
               << res.error().what();
    return folly::makeUnexpected(res.error());
  }

  // bpf_program__fd returns negative error codes on failure
  // third-party/libbpf/master/src/libbpf.c:bpf_program__fd()
  soProgFd_ = bpf_program__fd(soSkel_->progs.katran_de_so);
  if (soProgFd_ < 0) {
    LOG(ERROR) << "Failed to get FD of katran_de_so";
    return folly::makeUnexpected(
        std::system_error(
            errno,
            std::generic_category(),
            "Failed to get FD of katran_de_so"));
  }
  // NOTE: even if client and server do end up on the same host, with mount ns
  // both will get its own bpffs, therefore this should not conflict
  // (a job running as client and server shivless would not be expected)
  res =
      pin(soSkel_->maps.bss,
          KdeBpfUtil::getPinPath(KdeSoBssName),
          soProgFd_,
          KdeBpfUtil::getPinPath(KdeSockOpsProgName));
  if (!res) {
    LOG(ERROR) << "Failed to pin bpf data: " << res.error().what();
  }
  facebook::fb303::fbData->setCounter(
      "katran_de." + modeStr(getDirectEncapMode()) + ".error.pin_bss.so",
      res ? 0 : 1);

  if (bpf_prog_attach(
          soProgFd_, cgroupFd_, BPF_CGROUP_SOCK_OPS, BPF_F_ALLOW_MULTI)) {
    LOG(ERROR) << "Cgroup attach error";
    return folly::makeUnexpected(
        std::system_error(
            errno,
            std::generic_category(),
            "Failed to get FD of katran_de_so"));
  }
  VLOG(1) << "Installed Katran DirectEncap SockOps prog";
  return folly::Unit();
}

kde_zone parseZones(
    const std::string& csvZones,
    decltype(oss_kde_zones)& zoneMap) {
  if (csvZones.empty()) {
    return KDE_ZONE_1;
  }
  if (csvZones == "none") {
    return KDE_ZONE_NONE;
  }
  if (csvZones == "all") {
    return KDE_ZONE_ALL;
  }

  std::vector<std::string> names;
  folly::split(',', csvZones, names);
  kde_zone zones = KDE_ZONE_NONE;
  for (const auto& name : names) {
    bool found = false;
    for (const auto& zone : zoneMap) {
      if (name == zone.zone_name) {
        zones |= zone.bit;
        found = true;
        break;
      }
    }
    if (!found) {
      LOG(FATAL) << "Invalid KDE zone: " << name;
    }
  }
  return zones;
}

std::vector<std::string> BaseDirectEncap::zoneNames(kde_zone zones) const {
  if (zones == KDE_ZONE_NONE) {
    return {"none"};
  }
  if (zones == KDE_ZONE_ALL) {
    return {"all"};
  }
  std::vector<std::string> names;
  for (const auto& zone : zoneMap_) {
    if (zones & zone.bit) {
      names.emplace_back(zone.zone_name);
    }
  }
  if (names.empty()) {
    names.emplace_back("unknown");
  }
  return names;
}

kde_stats BaseDirectEncap::getSoStats() {
  return KdeBpfUtil::aggregateSoStats(*soSkel_->bss);
}

void BaseDirectEncap::setLogSockopsVars() {
  soSkel_->rodata->g_kde_log_config.log_level = logLevel_;
  soSkel_->rodata->g_kde_log_config.filter_log_level = filterLogLevel_;
  soSkel_->rodata->g_kde_log_config.local_port = logLocalPort_;

  // note htonl use instead of htons, we're assigning BE 32bit value
  // because struct bpf_sock_ops has 32bit field for remote port value.
  soSkel_->rodata->g_kde_log_config.remote_port = htonl(logRemotePort_);

  CHECK_EQ(
      sizeof(soSkel_->rodata->g_kde_log_config.remote_v6addr),
      logRemoteAddr_.byteCount());
  memcpy(
      soSkel_->rodata->g_kde_log_config.remote_v6addr,
      logRemoteAddr_.bytes(),
      logRemoteAddr_.byteCount());
  VLOG(1) << "kde_log_config: log level: " << logLevel_
          << ", filter log level: ";
}

folly::Expected<folly::Unit, std::system_error>
BaseDirectEncap::crashRecovery() {
  if (!pin_) { // eventually, should be true by default so we remove this
    return folly::Unit();
  }
  // in the rare case where a bpf prog is attached but we have no fd pinned to
  // fs, we end up in a inconsistent state and de ctl CANNOT recover from it. bc
  // we have no way to discover the prog due to the fact that we run in userns
  // in tw.
  bool hasPinnedArtifacts = false;
  for (const auto& name :
       {KdeTcBssName,
        KdeSoBssName,
        KdeTcProgName,
        KdeSockOpsProgName,
        KdeTcLinkName}) {
    auto path = KdeBpfUtil::getPinPath(name);
    VLOG(1) << "Checking pin path: " << path;
    if (::access(path.c_str(), F_OK) == 0) {
      LOG(WARNING) << "Found pinned artifact (likely crash): " << path;
      hasPinnedArtifacts = true;
      break;
    }
  }
  if (!hasPinnedArtifacts) {
    return folly::Unit();
  }
  auto cr = clean(cgroupPath_, iface_, 0); // handle=0 removes all
  if (cr.hasError()) {
    LOG(ERROR) << "Failed to clean old programs during crash recovery: "
               << cr.error().what();
    return folly::makeUnexpected(cr.error());
  }
  return folly::Unit();
}

folly::Expected<folly::Unit, std::system_error> BaseDirectEncap::clean(
    const std::string& cgroupPath,
    const std::string& iface,
    uint32_t tcHandle) {
  auto tcResult = cleanTC(iface, tcHandle);
  auto scResult = cleanSockOps(cgroupPath);
  rmPinned();
  if (tcResult.hasError()) {
    LOG(ERROR) << "Failed to clean Katran DirectEncap TC program: "
               << tcResult.error().what();
  }
  if (scResult.hasError()) {
    LOG(ERROR) << "Failed to clean Katran DirectEncap SockOps program: "
               << scResult.error().what();
  }
  if (tcResult.hasError()) {
    return tcResult;
  }
  if (scResult.hasError()) {
    return scResult;
  }
  LOG(INFO) << "Katran DirectEncap is cleaned up";
  return folly::Unit();
}

folly::Expected<folly::Unit, std::system_error> BaseDirectEncap::cleanSockOps(
    const std::string& cgroupPath) {
  if (cgroupPath.empty()) {
    LOG(ERROR) << "Cgroup path must be set";
    return folly::makeUnexpected(
        std::system_error(
            EINVAL, std::generic_category(), "Cgroup path must be set"));
  }

  std::string pPath = KdeBpfUtil::getPinPath(KdeSockOpsProgName);
  int pFd = bpf_obj_get(pPath.c_str());
  if (pFd < 0) {
    int err = errno;
    if (err == ENOENT) {
      LOG(WARNING) << "No pinned sockops prog found at " << pPath
                   << ", skipping sockops detach";
      return folly::Unit();
    }
    LOG(ERROR) << "Failed to open pinned sockops prog at " << pPath << ": "
               << folly::errnoStr(err);
    return folly::makeUnexpected(
        std::system_error(
            err, std::generic_category(), "Failed to open pinned sockops"));
  }
  SCOPE_EXIT {
    ::close(pFd);
  };

  int cgroupFd = ::open(cgroupPath.c_str(), O_DIRECTORY | O_RDONLY);
  if (cgroupFd < 0) {
    int err = errno;
    LOG(ERROR) << "Failed to open cgroup " << cgroupPath;
    return folly::makeUnexpected(
        std::system_error(
            err, std::generic_category(), "Failed to open cgroup"));
  }
  SCOPE_EXIT {
    ::close(cgroupFd);
  };

  VLOG(1) << "Using prog=" << pPath << " cgroupPath=" << cgroupPath;
  if (bpf_prog_detach2(pFd, cgroupFd, BPF_CGROUP_SOCK_OPS) != 0) {
    int err = errno;
    LOG(ERROR) << "Failed to detach pinned sockops: " << folly::errnoStr(err);
    return folly::makeUnexpected(
        std::system_error(
            err, std::generic_category(), "Failed to detach pinned sockops"));
  }
  LOG(INFO) << "Detached sockops prog via pinned path";
  return folly::Unit();
}

folly::Expected<folly::Unit, std::system_error> BaseDirectEncap::cleanTC(
    const std::string& iface,
    uint32_t handle) {
  int ifIndex = if_nametoindex(iface.c_str());
  if (!ifIndex) {
    int err = errno;
    std::string errMsg = "Can't resolve ifindex for interface " + iface;
    LOG(ERROR) << errMsg;
    return folly::makeUnexpected(
        std::system_error(err, std::generic_category(), errMsg));
  }

  // Host mode attaches via tcx link; rmPinned() unlinks and detaches it.
  if (::access(KdeBpfUtil::getPinPath(KdeTcLinkName).c_str(), F_OK) == 0) {
    return folly::Unit();
  }

  std::string pPath = KdeBpfUtil::getPinPath(KdeTcProgName);
  int pFd = bpf_obj_get(pPath.c_str());
  if (pFd < 0) {
    int err = errno;
    if (err == ENOENT) {
      LOG(WARNING) << "No pinned TC prog found at " << pPath
                   << ", skipping TC detach";
      return folly::Unit();
    }
    LOG(ERROR) << "Failed to open pinned TC prog at " << pPath << ": "
               << folly::errnoStr(err);
    return folly::makeUnexpected(
        std::system_error(
            err, std::generic_category(), "Failed to open pinned TC prog"));
  }
  SCOPE_EXIT {
    ::close(pFd);
  };

  katran::BpfAdapter adapter(/*set_limits=*/false);
  int ret = adapter.deleteTcBpfFilter(
      pFd,
      ifIndex,
      KdeTcProgName,
      KdeTcFilterPriority,
      katran::TC_EGRESS,
      handle);
  if (ret < 0) {
    int err = errno;
    std::string errMsg =
        "Failed to delete katran_de_tc from interface " + iface;
    LOG(ERROR) << errMsg;
    return folly::makeUnexpected(
        std::system_error(err, std::generic_category(), errMsg));
  }
  LOG(INFO) << "Deleted katran_de_tc from interface " << iface;
  return folly::Unit();
}

folly::Expected<folly::Unit, std::system_error> BaseDirectEncap::pin(
    bpf_map* map_bss,
    const std::string& bssPath,
    int progFd,
    const std::string& progPath) {
  if (!pin_) {
    return folly::Unit();
  }
  int bss_fd = bpf_map__fd(map_bss);
  if (bss_fd < 0) {
    return folly::makeUnexpected(
        std::system_error(
            errno, std::generic_category(), "Failed to get bss_fd"));
  }
  /* Don't clean up pinned path before pinning - if force-killed, the old BPF
   * program remains attached and will claim the TCP option slot first,
   * causing EEXIST (-17) on bpf_setsockopt(TCP_BPF_WRITE_HDR_OPT). Must
   * detach old program before cleanup. */
  if (bpf_obj_pin(bss_fd, bssPath.c_str()) != 0) {
    return folly::makeUnexpected(
        std::system_error(
            errno,
            std::generic_category(),
            folly::to<std::string>("Failed to pin BSS map at ", bssPath)));
  }
  VLOG(1) << "BSS maps pinned at " << bssPath;

  // NOT verifying prog fd as its done by the caller
  if (bpf_obj_pin(progFd, progPath.c_str()) != 0) {
    int saved_errno = errno;
    LOG(ERROR) << "bpf_obj_pin failed: fd=" << progFd << " path=" << progPath
               << " errno=" << saved_errno << " ("
               << folly::errnoStr(saved_errno) << ")";
    return folly::makeUnexpected(
        std::system_error(
            saved_errno,
            std::generic_category(),
            folly::to<std::string>("Failed to pin program at ", progPath)));
  }
  VLOG(1) << "BPF prog pinned at " << progPath;
  return folly::Unit();
}

void BaseDirectEncap::rmPinned() {
  for (const auto& name :
       {KdeTcBssName,
        KdeSoBssName,
        KdeTcProgName,
        KdeSockOpsProgName,
        KdeTcLinkName}) {
    std::string path = KdeBpfUtil::getPinPath(name);
    // semantically clearer to "unpinning"
    if (::unlink(path.c_str()) != 0) {
      int savedErrno = errno;
      if (savedErrno != ENOENT && savedErrno != EROFS) {
        LOG(ERROR) << "Pinned data present and failed to remove. Path: " << path
                   << ": " << folly::errnoStr(savedErrno);
      }
      VLOG(1) << "No pinned data to remove at " << path;
    } else {
      VLOG(1) << "Removed pinned data at " << path;
    }
  }
}

std::string BaseDirectEncap::modeStr(DirectEncapMode mode) {
  switch (mode) {
    case DirectEncapMode::CLIENT:
      return "client";
    case DirectEncapMode::SERVER:
      return "server";
    default:
      LOG(FATAL) << "Invalid DirectEncapMode " << (uint8_t)mode;
  }
}

} // namespace katran_tpr
