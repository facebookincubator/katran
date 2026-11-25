#include <katran/kde/core/ClientDirectEncap.h>

#include <folly/String.h>
#include <glog/logging.h>
#include <net/if.h>
#include <system_error>

#include <katran/kde/consts.h>
#include <katran/lib/IpHelpers.h>
#include "fb303/ServiceData.h"
#include "katran/kde/core/KdeBpfUtil.h"

namespace katran_tpr {

ClientDirectEncap::ClientDirectEncap(
    const std::string& iface,
    kde_zone clientZone,
    decltype(oss_kde_zones)& zoneMap,
    VipEnablementMode vipEnablementMode,
    bool set_limits,
    const std::string& configPath,
    const std::string& cluster,
    GuePort encapPort,
    bool hostMode,
    bool natMode)
    : BaseDirectEncap(iface, zoneMap, set_limits),
      tcSkel_(BpfSkeleton<katran_de_tc_bpf>::make()),
      clientZone_(clientZone),
      encapPort_(encapPort),
      hostMode_(hostMode),
      natMode_(natMode) {
  switch (vipEnablementMode) {
    case VipEnablementMode::ALL_ENABLED:
      enableForAllVips_ = true;
      break;
    case VipEnablementMode::CONFIG_GATED:
      CHECK(!configPath.empty())
          << "VipEnablementMode was set to CONFIG_GATED, but no config provided";
      CHECK(!cluster.empty())
          << "VipEnablementMode was set to CONFIG_GATED, but cluster not specified";
      kdeConfigPoller_ =
          std::make_unique<KdeConfigPoller>(this, configPath, cluster);
      break;
    case VipEnablementMode::MANUAL:
      break;
    default:
      LOG(FATAL) << "Invalid VipEnablementMode provided";
  }
  VLOG(1) << "kde client zone is " << clientZoneStr() << " value "
          << clientZone;
}

ClientDirectEncap::~ClientDirectEncap() {
  shutdown();
}

folly::Expected<folly::Unit, std::system_error> ClientDirectEncap::init() {
  auto res = crashRecovery();
  if (!res) {
    return res;
  }
  res = loadSockOps();
  if (!res) {
    return res;
  }
  res = loadTc();
  if (!res) {
    return res;
  }

  if (kdeConfigPoller_) {
    auto runConfigPollerResult = kdeConfigPoller_->runConfigPoller();
    if (runConfigPollerResult.hasError()) {
      return folly::makeUnexpected(runConfigPollerResult.error());
    }
  }

  return folly::Unit();
}

void ClientDirectEncap::detach() {
  soProgFd_ = 0;
  tcProgFd_ = 0;
}

void ClientDirectEncap::shutdown() {
  if (kdeConfigPoller_) {
    kdeConfigPoller_->shutdown();
  }

  if (soProgFd_) {
    if (bpf_prog_detach2(soProgFd_, cgroupFd_, BPF_CGROUP_SOCK_OPS)) {
      LOG(ERROR) << "Failed detach katan_de sock_ops prog";
    }
    close(cgroupFd_);
  }
  /* either TCX or legacy TC */
  if (tcLink_) {
    // Closes our fd. The kernel detaches the program once the link has no
    // references left; a pinned link stays until rmPinned() below unpins it.
    bpf_link__destroy(tcLink_);
    tcLink_ = nullptr;
  } else if (tcProgFd_) {
    adapter_.deleteTcBpfFilter(
        tcProgFd_,
        ifIndex_,
        KdeTcProgName,
        KdeTcFilterPriority,
        katran::TC_EGRESS,
        tcProgId_);
  }
  // Only clean pinned BSS if we actually detached programs.
  // In detach mode, FDs are zeroed and programs are left running,
  // so BSS maps must remain pinned for the programs to function.
  if (soProgFd_ || tcProgFd_) {
    rmPinned();
  }
}

void ClientDirectEncap::onVipAdded(
    const ti::shiv::kde_vips_rollout::KdeVip& kdeVip) {
  if (folly::copy(kdeVip.protocol().value()) !=
      ti::shiv::kde_vips_rollout::KdeProtocol::TCP) {
    // Right now, we only deal with TCP vips for KDE
    return;
  }

  // If we extend support to ipv4, we would have to change this.
  auto vip_addr = katran::IpHelpers::parseAddrToBe(kdeVip.address().value());
  kde_vip vip = {};
  std::memcpy(vip.dstv6, vip_addr.v6daddr, 16);

  uint32_t port = folly::copy(kdeVip.port().value());
  vip.dst_port = folly::Endian::big(port);

  // The value that the vip is mapped to is not relevant. It's just the
  // existence of the vip as a key in the map that determines whether or
  // not kde is enabled.
  uint8_t dummyValue = 1;

  auto res = adapter_.bpfUpdateMap(
      bpf_map__fd(soSkel_->maps.kde_vip_map), &vip, &dummyValue);

  if (res != 0) {
    // TODO: Increment an ODS counter
    LOG(ERROR) << "Failed to enable KDE for vip with addr = "
               << kdeVip.address().value() << "and port "
               << folly::copy(kdeVip.port().value())
               << " due to a failure to add to the  BPF map. Error is "
               << folly::errnoStr(errno);
  }
}

void ClientDirectEncap::onVipDeleted(
    const ti::shiv::kde_vips_rollout::KdeVip& kdeVip) {
  if (folly::copy(kdeVip.protocol().value()) !=
      ti::shiv::kde_vips_rollout::KdeProtocol::TCP) {
    // Right now, we only deal with TCP vips for KDE
    return;
  }

  // If we extend support to ipv4, we would have to change this.
  auto vip_addr = katran::IpHelpers::parseAddrToBe(kdeVip.address().value());
  kde_vip vip = {};
  std::memcpy(vip.dstv6, vip_addr.v6daddr, 16);

  uint32_t port = folly::copy(kdeVip.port().value());
  vip.dst_port = folly::Endian::big(port);

  auto res = adapter_.bpfMapDeleteElement(
      bpf_map__fd(soSkel_->maps.kde_vip_map), &vip);

  if (res != 0) {
    // TODO: Increment an ODS counter
    LOG(ERROR) << "Failed to disable KDE for vip with addr = "
               << kdeVip.address().value() << ", port=" << port
               << " due to a failure to add to the  BPF map. Error is "
               << folly::errnoStr(errno);
  }
}

folly::Expected<folly::Unit, std::system_error>
ClientDirectEncap::setSockopsVars() {
  soSkel_->rodata->g_direct_encap_mode =
      static_cast<int>(DirectEncapMode::CLIENT);
  soSkel_->rodata->g_enable_for_all_vips = enableForAllVips_;
  soSkel_->rodata->g_kde_client_zone = clientZone_;
  soSkel_->rodata->g_kde_encap_port = static_cast<uint16_t>(encapPort_);
  soSkel_->rodata->g_kde_client_host_mode = hostMode_;
  soSkel_->rodata->g_kde_client_nat_mode = natMode_;
  /* tuple store is required only by host mode, shrink it to reduce mem util on
   * container mode */
  if (!hostMode_ &&
      bpf_map__set_max_entries(soSkel_->maps.katran_de_tuple_store, 1)) {
    LOG(ERROR) << "Failed to shrink katran_de_tuple_store";
    return folly::makeUnexpected(
        std::system_error(
            errno, std::generic_category(), "Failed to set max entries"));
  }
  return folly::Unit();
}

folly::Expected<folly::Unit, std::system_error> ClientDirectEncap::loadTc() {
  ifIndex_ = if_nametoindex(iface_.c_str());
  if (!ifIndex_) {
    LOG(ERROR) << "Can't resolve ifindex for interface " << iface_;
    return folly::makeUnexpected(
        std::system_error(errno, std::generic_category(), ""));
  }

  auto res = tcSkel_.open();
  if (!res) {
    LOG(ERROR) << "Failed to open Katran DirectEncap TC prog "
               << res.error().what();
    return folly::makeUnexpected(res.error());
  }
  tcSkel_->rodata->g_kde_client_host_mode = hostMode_;
  if (hostMode_) {
    // tcx links reject programs not loaded for a tcx attach type
    bpf_program__set_expected_attach_type(
        tcSkel_->progs.katran_de_tc, BPF_TCX_EGRESS);
  }

  auto soMapFd = bpf_map__fd(soSkel_->maps.katran_de_sk_store);
  if (soMapFd < 0) {
    LOG(ERROR) << "Failed to get fd of katran_de_sk_store";
    return folly::makeUnexpected(
        std::system_error(errno, std::generic_category(), "Failed to get fd"));
  }
  if (bpf_map__reuse_fd(tcSkel_->maps.katran_de_sk_store, soMapFd)) {
    LOG(ERROR) << "Failed to reuse katran_de_sk_store";
    return folly::makeUnexpected(
        std::system_error(
            errno, std::generic_category(), "Failed to reuse fd"));
  }

  auto soTupleMapFd = bpf_map__fd(soSkel_->maps.katran_de_tuple_store);
  if (soTupleMapFd < 0) {
    LOG(ERROR) << "Failed to get fd of katran_de_tuple_store";
    return folly::makeUnexpected(
        std::system_error(errno, std::generic_category(), "Failed to get fd"));
  }
  if (bpf_map__reuse_fd(tcSkel_->maps.katran_de_tuple_store, soTupleMapFd)) {
    LOG(ERROR) << "Failed to reuse katran_de_tuple_store";
    return folly::makeUnexpected(
        std::system_error(
            errno, std::generic_category(), "Failed to reuse fd"));
  }

  res = tcSkel_.load();
  if (!res) {
    LOG(ERROR) << "Failed to load Katran DirectEncap TC prog"
               << res.error().what();
    return folly::makeUnexpected(res.error());
  }

  // bpf_program__fd returns negative error codes on failure
  // third-party/libbpf/master/src/libbpf.c:bpf_program__fd()
  tcProgFd_ = bpf_program__fd(tcSkel_->progs.katran_de_tc);
  if (tcProgFd_ < 0) {
    LOG(ERROR) << "Failed to get FD of katran_de_tc";
    return folly::makeUnexpected(
        std::system_error(
            errno,
            std::generic_category(),
            "Failed to get FD of katran_de_tc"));
  }

  res =
      pin(tcSkel_->maps.bss,
          KdeBpfUtil::getPinPath(KdeTcBssName),
          tcProgFd_,
          KdeBpfUtil::getPinPath(KdeTcProgName));
  if (!res) {
    LOG(ERROR) << "Failed to pin Katran DirectEncap TC prog: "
               << res.error().what();
  }
  facebook::fb303::fbData->setCounter(
      "katran_de." + modeStr(getDirectEncapMode()) + ".error.pin_bss.tc",
      res ? 0 : 1);

  tcProgId_ = katran::BaseBpfAdapter::getBpfProgInfo(tcProgFd_).id;

  if (hostMode_) {
    // Host mode runs on the host NIC, where a CNI's tcx program (e.g. Cilium)
    // returns a final verdict, so legacy tc filters after it never run. Attach
    // via tcx at the head instead.
    LIBBPF_OPTS(bpf_tcx_opts, tcxOpts, .flags = BPF_F_BEFORE);
    tcLink_ = bpf_program__attach_tcx(
        tcSkel_->progs.katran_de_tc, ifIndex_, &tcxOpts);
    if (!tcLink_) {
      int savedErrno = errno;
      LOG(ERROR) << "Can't attach TC bpf to interface via tcx (needs kernel "
                 << ">= 6.6): " << folly::errnoStr(savedErrno);
      return folly::makeUnexpected(
          std::system_error(
              savedErrno, std::generic_category(), "Failed to attach tcx"));
    }
    // TODO(shah256): make pin fatal (TCX not pinned means prog is not running)
    // and then let pin also pin TCX if host mode, this part of the code can
    // then be removed
    if (pin_) {
      auto linkPath = KdeBpfUtil::getPinPath(KdeTcLinkName);
      if (bpf_link__pin(tcLink_, linkPath.c_str())) {
        int savedErrno = errno;
        LOG(ERROR) << "Failed to pin tcx link at " << linkPath << ": "
                   << folly::errnoStr(savedErrno);
        return folly::makeUnexpected(
            std::system_error(
                savedErrno, std::generic_category(), "Failed to pin tcx"));
      }
    }
    VLOG(1) << "Attached Katran DirectEncap TC prog to " << iface_
            << " via tcx";
  } else if (tcProgFd_) {
    /* We use tcProgId_ as a unique handle to make sure we delete only this
     * program on shutdown. Otherwise, what seems to happen is that it deletes
     * all programs with the specified priority and name, even though we're
     * passing in the program fd */
    if (adapter_.addTcBpfFilter(
            tcProgFd_,
            ifIndex_,
            KdeTcProgName,
            KdeTcFilterPriority,
            katran::TC_EGRESS,
            tcProgId_)) {
      LOG(ERROR) << "Can't attach TC bpf to interface";
      return folly::makeUnexpected(
          std::system_error(
              errno, std::generic_category(), "Failed to attach TC prog"));
    }
    VLOG(1) << "Attached Katran DirectEncap TC prog to " << iface_;
  }
  return folly::Unit();
}

kde_tc_stats ClientDirectEncap::getTcStats() {
  return KdeBpfUtil::aggregateTcStats(*tcSkel_->bss);
}

DirectEncapMode ClientDirectEncap::getDirectEncapMode() const {
  return DirectEncapMode::CLIENT;
}

std::string ClientDirectEncap::clientZoneStr() const {
  return folly::join(",", zoneNames(clientZone_));
}

} // namespace katran_tpr
