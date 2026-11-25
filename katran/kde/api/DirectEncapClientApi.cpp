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

#include "katran/kde/api/DirectEncapClientApi.h"

#include <folly/Singleton.h>
#include <folly/logging/xlog.h>

using namespace katran_tpr;

namespace katran_de {

static folly::Singleton<DirectEncapClientApi, ClientTag> kdeApiSingleton;

std::shared_ptr<DirectEncapClientApi> DirectEncapClientApi::getInstance() {
  return kdeApiSingleton.try_get();
}

bool DirectEncapClientApi::installWithParams(const KdeInstallParams& params) {
  auto instance = getInstance();
  if (!instance) {
    XLOG(ERR) << "Failed to get client singleton instance";
    return false;
  }
  /* check rollout upfront and don't install if it evals to false */
  const bool enabled = !params.rolloutCheck ||
      rolloutEnabled(params.rolloutCheck, /*valueOnError=*/false);
  /* `enabled` reports what the config asks for
   * `running` is set once the BPF progs are attached */
  facebook::fb303::fbData->setCounter(
      "katran_de.client.enabled", enabled ? 1 : 0);
  if (!enabled) {
    XLOG(INFO)
        << "Katran DirectEncap Client is disabled, skipping installation";
    return true;
  }

  if (!instance->DirectEncapApiBase::installWithParamsImpl(params)) {
    return false;
  }
  /* keep watching the rollout check only while we stay attached */
  if (!params.detach && params.rolloutCheck) {
    instance->checkKillswitch();
  }
  return true;
}

void DirectEncapClientApi::uninstall() {
  auto instance = getInstance();
  if (!instance) {
    XLOG(ERR) << "Failed to get client singleton instance";
    return;
  }
  instance->uninstallImpl();
}

DirectEncapClientStats DirectEncapClientApi::stats() {
  auto instance = getInstance();
  if (!instance) {
    XLOG(ERR) << "Failed to get client singleton instance";
    return DirectEncapClientStats{};
  }
  return instance->getStatsImpl();
}

bool DirectEncapClientApi::initImpl(const KdeInstallParams& params) {
  if (deClient_) {
    XLOG(ERR) << "Katran DirectEncap Client is already initialized";
    return false;
  }
  if (params.hostMode && params.detach && !params.pin) {
    // host mode attaches tc via tcx, which the kernel removes when the process
    // exits unless the link is pinned
    XLOG(ERR) << "Host mode install requires pinning (--pin-bss)";
    return false;
  }
  katran_tpr::GuePort guePort = katran_tpr::GuePort::DEFAULT; // encapport
  if (params.kdePort) {
    guePort = katran_tpr::GuePort::KDE;
  }

  // a client is in exactly one zone
  if (params.clientZone.find(',') != std::string::npos ||
      params.clientZone == "all") {
    XLOG(FATAL) << "Invalid KDE client zone: " << params.clientZone;
  }

  // Create the underlying client object.
  auto client = std::make_unique<ClientDirectEncap>(
      params.iface,
      katran_tpr::parseZones(params.clientZone, params.zone_map),
      params.zone_map,
      VipEnablementMode::ALL_ENABLED,
      /*set_limits=*/params.rlimitMemLock,
      /*configPath=*/"",
      /*cluster=*/"",
      /*GuePort=*/guePort,
      /*hostMode=*/params.hostMode,
      /*natMode=*/params.natMode);
  // TODO(shah256): remove the setters and just use constructor
  client->setCgroupPath(params.cgroupPath);
  client->setPin(params.pin);
  auto res = client->init();
  if (res.hasError()) {
    XLOG(ERR) << "Katran DirectEncap Client failed to initialize, ERR: "
              << res.error().what();
    return false;
  }

  if (params.detach) {
    XLOG(INFO)
        << "Katran DirectEncap Client initialized (detached) successfully with zone "
        << client->clientZoneStr();
    client->detach();
    client.reset();
    return true;
  }

  XLOG(INFO) << "Katran DirectEncap Client initialized successfully with zone "
             << client->clientZoneStr();
  facebook::fb303::fbData->setCounter("katran_de.client.running", 1);
  deClient_ = std::move(client);
  return true;
}

void DirectEncapClientApi::uninstallImpl() {
  std::lock_guard<std::mutex> lock(mutex_);
  kdeStatsPoller_.reset();
  kdeStatsOtel_.reset();
  katran_tpr::KdeStatsOtel::shutdownGlobal();
  if (deClient_) {
    deClient_.reset();
    XLOG(INFO) << "Katran DirectEncap Client shutdown";
  }
  facebook::fb303::fbData->setCounter("katran_de.client.running", 0);
}

DirectEncapClientStats DirectEncapClientApi::getStatsImpl() {
  std::lock_guard<std::mutex> lock(mutex_);
  DirectEncapClientStats stats;
  if (!deClient_) {
    XLOG(ERR) << "Katran DirectEncap Client is not initialized";
    return stats;
  }
  stats.so_stats = deClient_->getSoStats();
  stats.tc_stats = deClient_->getTcStats();
  return stats;
}

void DirectEncapClientApi::checkKillswitch() {
  auto* evb = evbThread_.getEventBase();
  evb->runImmediatelyOrRunInEventBaseThread([this, evb, stopped = stopped_] {
    evb->runAfterDelay(
        [this, stopped] {
          if (*stopped) {
            return;
          }
          if (rolloutEnabled(rolloutCheck_, /*valueOnError=*/true)) {
            checkKillswitch();
          } else {
            XLOG(INFO)
                << "Client killswitch disabled the feature, uninstalling...";
            *stopped = true;
            uninstallImpl();
            facebook::fb303::fbData->setCounter("katran_de.client.enabled", 0);
          }
        },
        kRolloutCheckIntervalMs);
  });
}

} // namespace katran_de
