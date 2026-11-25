#include "katran/kde/core/KdeConfigPoller.h"

using ti::shiv::kde_vips_rollout::KdeVip;

namespace katran_tpr {

KdeConfigPoller::KdeConfigPoller(
    KdeConfigPollerCallback* callback,
    const std::string& configPath,
    const std::string& cluster)
    : callback_(callback), kdeConfig_(configPath), cluster_(cluster) {}

KdeConfigPoller::~KdeConfigPoller() {
  shutdown();
}

void KdeConfigPoller::shutdown() {
  kdeConfig_.unsetCallback();
  VLOG(2) << "KDE config poller is shutting down..";
}

folly::Expected<folly::Unit, std::system_error>
KdeConfigPoller::runConfigPoller() {
  readConfigAndMakeUpdates();
  auto cb = [this](const std::string& /*configName*/) {
    readConfigAndMakeUpdates();
  };
  kdeConfig_.setCallback(cb);
  kdeConfig_.subscribeToConfig();
  return folly::Unit();
}

void KdeConfigPoller::readConfigAndMakeUpdates() {
  /*
   * In order to get all of the enabled vips, we look at the union of
   * config.globally_enabled_vips and
   * config.source_cluster_to_enabled_vips[cluster]
   */

  if (auto configPtr = kdeConfig_.get()) {
    folly::F14FastSet<KdeVip, KdeVipHasher> enabledVips;
    for (const auto& kdeVip : configPtr->globally_enabled_vips().value()) {
      enabledVips.insert(kdeVip);
    }

    const auto& clusterToEnabledVips =
        configPtr->source_cluster_to_enabled_vips().value();
    if (clusterToEnabledVips.find(cluster_) != clusterToEnabledVips.end()) {
      for (const auto& kdeVip : clusterToEnabledVips.at(cluster_)) {
        enabledVips.insert(kdeVip);
      }
    }

    // Get all of the vips that are no longer enabled, and call onVipDeleted
    for (const auto& previouslyEnabledVip : previouslyEnabledVips_) {
      if (!enabledVips.contains(previouslyEnabledVip)) {
        callback_->onVipDeleted(previouslyEnabledVip);
      }
    }

    // Get all of the vips that are enabled but weren't previously, and call
    // onVipAdded
    for (const auto& enabledVip : enabledVips) {
      if (!previouslyEnabledVips_.contains(enabledVip)) {
        callback_->onVipAdded(enabledVip);
      }
    }

    previouslyEnabledVips_ = std::move(enabledVips);
  } else {
    LOG(ERROR) << "Failed to read KDE config";
  }
}

} // namespace katran_tpr
