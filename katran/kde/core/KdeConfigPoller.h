#pragma once

#include <common/config/ConfigeratorConfig.h>
#include <configerator/structs/ti/shiv/gen-cpp2/kde_vips_rollout_types.h>

namespace katran_tpr {

struct KdeVipHasher {
  std::size_t operator()(
      const ::ti::shiv::kde_vips_rollout::KdeVip& kdeVip) const {
    auto addrHash = std::hash<std::string>()(kdeVip.address().value());
    auto portHash = std::hash<int32_t>()(folly::copy(kdeVip.port().value()));
    auto protocolHash = std::hash<::ti::shiv::kde_vips_rollout::KdeProtocol>()(
        folly::copy(kdeVip.protocol().value()));

    return addrHash ^ portHash ^ protocolHash;
  }
};

/*
 * This is used to poll the config for the KdeVip rollout. It is used
 * on the client side (i.e. Edge).
 *
 * The config that it reads in has two fields:
 * - globally_enabled_vips: This is a list of vips
 * - source_cluster_to_enabled_vips: This is a mapping from cluster name
 *   (e.g. "sea1c01") to a list of vips
 *
 * For a given cluster, the list of vips enabled for the cluster is the
 * union of globally_enabled_vips and source_cluster_to_enabled_vips[cluster].
 * When a vip is added or deleted from this list due to a config change,
 * the callbacks onVipAdded and onVipDeleted are triggered.
 */
class KdeConfigPoller {
 public:
  class KdeConfigPollerCallback {
   public:
    virtual ~KdeConfigPollerCallback() = default;
    KdeConfigPollerCallback() = default;
    KdeConfigPollerCallback(const KdeConfigPollerCallback&) = delete;
    KdeConfigPollerCallback& operator=(const KdeConfigPollerCallback&) = delete;
    KdeConfigPollerCallback(KdeConfigPollerCallback&&) = delete;
    KdeConfigPollerCallback& operator=(KdeConfigPollerCallback&&) = delete;

    virtual void onVipAdded(
        const ti::shiv::kde_vips_rollout::KdeVip& kdeVip) = 0;

    virtual void onVipDeleted(
        const ti::shiv::kde_vips_rollout::KdeVip& kdeVip) = 0;
  };

  KdeConfigPoller(
      KdeConfigPollerCallback* callback,
      const std::string& configPath,
      const std::string& cluster);

  ~KdeConfigPoller();
  KdeConfigPoller(const KdeConfigPoller&) = delete;
  KdeConfigPoller& operator=(const KdeConfigPoller&) = delete;
  KdeConfigPoller(KdeConfigPoller&&) = delete;
  KdeConfigPoller& operator=(KdeConfigPoller&&) = delete;

  void shutdown();

  folly::Expected<folly::Unit, std::system_error> runConfigPoller();

  // Made public for testing purposes
  void readConfigAndMakeUpdates();

 private:
  KdeConfigPollerCallback* callback_;
  facebook::config::ConfigeratorConfig<::ti::shiv::kde_vips_rollout::opt_in>
      kdeConfig_;
  std::string cluster_;
  folly::F14FastSet<ti::shiv::kde_vips_rollout::KdeVip, KdeVipHasher>
      previouslyEnabledVips_;
};

} // namespace katran_tpr
