#include <folly/String.h>
#include <glog/logging.h>
#include <katran/kde/core/ServerDirectEncap.h>

namespace katran_tpr {

ServerDirectEncap::ServerDirectEncap(
    const std::string& iface,
    const folly::IPAddress& directAddress,
    kde_zone zones,
    decltype(oss_kde_zones)& zoneMap,
    bool set_limits,
    const std::optional<std::string>& vipsEnabled,
    const std::optional<std::string>& vipsDisabled)
    : BaseDirectEncap(iface, zoneMap, set_limits),
      directAddress_(directAddress),
      zones_(zones),
      vipsEnabled_(parseVips(vipsEnabled)),
      vipsDisabled_(parseVips(vipsDisabled)) {
  /* vip mode validations */
  if (vipsEnabled.has_value() && vipsDisabled.has_value()) {
    LOG(FATAL) << "both vipsEnabled and vipsDisabled cannot be used together";
  } else if (vipsEnabled.has_value()) {
    vipMode_ = KDE_VIP_FILTER_ALLOWLIST;
    LOG(INFO) << "Shivless server enabled for " << vipsEnabled_.size()
              << " vips. vipsEnabled=" << vipsEnabled.value();
  } else if (vipsDisabled.has_value()) {
    vipMode_ = KDE_VIP_FILTER_BLOCKLIST;
    LOG(INFO) << "Shivless server disabled for " << vipsDisabled_.size()
              << " vips. vipsDisabled=" << vipsDisabled.value();
  }
  if (vipsEnabled_.size() > KDE_MAX_VIPS_FILTER ||
      vipsDisabled_.size() > KDE_MAX_VIPS_FILTER) {
    throw std::runtime_error(
        fmt::format("Max filters allowed: {}", KDE_MAX_VIPS_FILTER));
  }
  VLOG(1) << "kde server zones: " << serverZonesStr();
}

ServerDirectEncap::~ServerDirectEncap() {
  shutdown();
}

folly::Expected<folly::Unit, std::system_error> ServerDirectEncap::init() {
  return loadSockOps();
}

void ServerDirectEncap::detach() {
  soProgFd_ = 0;
}

void ServerDirectEncap::shutdown() {
  if (soProgFd_) {
    if (bpf_prog_detach2(soProgFd_, cgroupFd_, BPF_CGROUP_SOCK_OPS)) {
      LOG(ERROR) << "Failed detach katan_de sock_ops prog";
    }
    close(soProgFd_);
    close(cgroupFd_);
    rmPinned();
  }
}

folly::Expected<folly::Unit, std::system_error>
ServerDirectEncap::setSockopsVars() {
  soSkel_->rodata->g_direct_encap_mode =
      static_cast<int>(DirectEncapMode::SERVER);
  if (directAddress_.empty()) {
    return folly::makeUnexpected(
        std::system_error(
            0, std::generic_category(), "Direct IPAddress must be set"));
  }
  if (!directAddress_.isV6()) {
    return folly::makeUnexpected(
        std::system_error(
            0, std::generic_category(), "Direct IPAddress must be V6"));
  }
  /* setup vips whitelist if enabled */
  if (vipMode_ == KDE_VIP_FILTER_ALLOWLIST) {
    soSkel_->rodata->g_vips_enabled_cnt = vipsEnabled_.size();
    soSkel_->rodata->g_vip_filter_mode = KDE_VIP_FILTER_ALLOWLIST;
    for (size_t i = 0; i < vipsEnabled_.size(); i++) {
      CHECK_EQ(
          sizeof(soSkel_->rodata->g_vips_enabled[i].v6addr),
          vipsEnabled_[i].byteCount());
      memcpy(
          soSkel_->rodata->g_vips_enabled[i].v6addr,
          vipsEnabled_[i].bytes(),
          vipsEnabled_[i].byteCount());
    }
  }
  /* setup vips blocklist if enabled */
  else if (vipMode_ == KDE_VIP_FILTER_BLOCKLIST) {
    soSkel_->rodata->g_vips_disabled_cnt = vipsDisabled_.size();
    soSkel_->rodata->g_vip_filter_mode = KDE_VIP_FILTER_BLOCKLIST;
    for (size_t i = 0; i < vipsDisabled_.size(); i++) {
      CHECK_EQ(
          sizeof(soSkel_->rodata->g_vips_disabled[i].v6addr),
          vipsDisabled_[i].byteCount());
      memcpy(
          soSkel_->rodata->g_vips_disabled[i].v6addr,
          vipsDisabled_[i].bytes(),
          vipsDisabled_[i].byteCount());
    }
  }
  /* copy addr and zones */
  CHECK_EQ(
      sizeof(soSkel_->rodata->g_direct_ip.v6addr), directAddress_.byteCount());
  memcpy(
      soSkel_->rodata->g_direct_ip.v6addr,
      directAddress_.bytes(),
      directAddress_.byteCount());
  soSkel_->rodata->g_kde_server_zones = zones_;
  soSkel_->rodata->g_kde_num_zones = std::size(zoneMap_);
  return folly::Unit();
}

DirectEncapMode ServerDirectEncap::getDirectEncapMode() const {
  return DirectEncapMode::SERVER;
}

std::vector<folly::IPAddress> ServerDirectEncap::parseVips(
    const std::optional<std::string>& csvVips) {
  std::vector<folly::IPAddress> vipsEnabled;
  std::vector<std::string> vips;

  if (!csvVips.has_value()) {
    return vipsEnabled;
  }

  folly::split(',', csvVips.value(), vips);
  for (const auto& vip : vips) {
    auto trimmedVip = std::string(folly::trimWhitespace(vip));
    if (trimmedVip.empty()) {
      continue;
    }
    auto maybeIp = folly::IPAddress::tryFromString(trimmedVip);
    if (maybeIp.hasError()) {
      LOG(FATAL) << "Invalid KDE VIP: " << trimmedVip;
    }
    if (!maybeIp->isV6()) {
      LOG(FATAL) << "KDE VIP must be IPv6: " << trimmedVip;
    }
    vipsEnabled.push_back(*maybeIp);
  }
  return vipsEnabled;
}

std::string ServerDirectEncap::serverZonesStr() const {
  return folly::join(",", zoneNames(zones_));
}

} // namespace katran_tpr
