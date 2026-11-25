/* Copyright (C) 2018-present, Facebook, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#pragma once

#include <folly/io/async/EventBaseManager.h>
#include <folly/io/async/ScopedEventBaseThread.h>
#include <glog/logging.h>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

#include "katran/kde/consts.h"
#include "katran/kde/core/KdeStatsOtel.h"
#include "katran/kde/core/KdeStatsPoller.h"

namespace katran_de {

bool rolloutEnabled(const std::function<bool()>& check, bool valueOnError);

struct KdeInstallParams {
  std::function<bool()> rolloutCheck;
  bool detach{false};
  bool rlimitMemLock{false};
  std::string cgroupPath;
  std::string iface;
  folly::IPAddress directIp;
  std::string clientZone;
  std::string serverZones;
  bool pin{false};
  bool kdePort{false};
  bool hostMode{false};
  std::optional<katran_tpr::KdeOtelOptions> otelStats;
  bool natMode{false};
  // vip mode items
  std::optional<std::string> vipsEnabled;
  std::optional<std::string> vipsDisabled;
  decltype(oss_kde_zones)& zone_map{oss_kde_zones};
};

class DirectEncapApiBase {
 public:
  DirectEncapApiBase() = default;
  virtual ~DirectEncapApiBase() {
    // Explicitly destroy stats pollers before evbThread_.
    kdeStatsPoller_.reset();
    kdeStatsOtel_.reset();
  }
  DirectEncapApiBase(const DirectEncapApiBase&) = delete;
  DirectEncapApiBase& operator=(const DirectEncapApiBase&) = delete;
  DirectEncapApiBase(DirectEncapApiBase&&) = delete;
  DirectEncapApiBase& operator=(DirectEncapApiBase&&) = delete;

  bool installWithParamsImpl(const KdeInstallParams& params);

 protected:
  virtual bool initImpl(const KdeInstallParams& params) = 0;
  virtual void uninstallImpl() = 0;
  virtual void checkKillswitch() = 0;

  virtual katran_tpr::BaseDirectEncap* getImpl() = 0;

  bool initialized();

  std::mutex mutex_;
  folly::ScopedEventBaseThread evbThread_{"katran_de"};
  std::unique_ptr<katran_tpr::KdeStatsPoller> kdeStatsPoller_;
  std::unique_ptr<katran_tpr::KdeStatsOtel> kdeStatsOtel_;
  std::shared_ptr<bool> stopped_{std::make_shared<bool>(false)};
  std::function<bool()> rolloutCheck_;

  static constexpr uint32_t kRolloutCheckIntervalMs = 60 * 1000;
};

} // namespace katran_de
