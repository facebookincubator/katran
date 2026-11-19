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

#include "katran/kde/api/DirectEncapServerApi.h"

#include <folly/Singleton.h>

namespace katran_de {

folly::Singleton<DirectEncapServerApi, ServerTag> kdeApiSingleton;

std::shared_ptr<DirectEncapServerApi> DirectEncapServerApi::getInstance() {
  return kdeApiSingleton.try_get();
}

bool DirectEncapServerApi::installWithParams(const KdeInstallParams& params) {
  auto instance = getInstance();
  if (!instance) {
    XLOG(ERR) << "Failed to get server singleton instance";
    return false;
  }
  /* check rollout upfront and don't install if it evals to false */
  const bool enabled = !params.rolloutCheck ||
      rolloutEnabled(params.rolloutCheck, /*valueOnError=*/false);
  /* `enabled` reports what the config asks for; `running`, set once the BPF
   * progs are attached, reports what actually happened. */
  facebook::fb303::fbData->setCounter(
      "katran_de.server.enabled", enabled ? 1 : 0);
  if (!enabled) {
    XLOG(INFO)
        << "Katran DirectEncap Server is disabled, skipping installation";
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

void DirectEncapServerApi::uninstall() {
  auto instance = getInstance();
  if (!instance) {
    XLOG(ERR) << "Failed to get server singleton instance";
    return;
  }
  instance->uninstallImpl();
}

DirectEncapServerStats DirectEncapServerApi::stats() {
  auto instance = getInstance();
  if (!instance) {
    XLOG(ERR) << "Failed to get server singleton instance";
    return DirectEncapServerStats{};
  }
  return instance->getStatsImpl();
}

bool DirectEncapServerApi::initImpl(const KdeInstallParams& params) {
  if (deServer_) {
    XLOG(ERR) << "Katran DirectEncap Server is already initialized";
    return false;
  }
  if (params.directIp.empty()) {
    XLOG(ERR) << "Katran DirectEncap Server needs a direct IP address";
    return false;
  }

  auto server = std::make_unique<katran_tpr::ServerDirectEncap>(
      params.iface,
      params.directIp,
      params.serverZones,
      params.rlimitMemLock,
      params.vipsEnabled,
      params.vipsDisabled);
  server->setCgroupPath(params.cgroupPath);
  server->setPin(params.pin);
  auto res = server->init();
  if (res.hasError()) {
    XLOG(ERR) << "Katran DirectEncap Server failed to initialize, ERR: "
              << res.error().what();
    return false;
  }

  if (params.detach) {
    server->detach();
    server.reset();
    XLOG(INFO)
        << "Katran DirectEncap Server initialized (detached) successfully with zones: "
        << server->serverZonesStr();
    return true;
  }

  XLOG(INFO)
      << "Katran DirectEncap Server initialized successfully with zones: "
      << server->serverZonesStr();
  facebook::fb303::fbData->setCounter("katran_de.server.running", 1);
  deServer_ = std::move(server);
  return true;
}

void DirectEncapServerApi::uninstallImpl() {
  std::lock_guard<std::mutex> lock(mutex_);
  kdeStatsPoller_.reset();
  if (deServer_) {
    deServer_.reset();
    XLOG(INFO) << "Katran DirectEncap Server shutdown";
  }
  facebook::fb303::fbData->setCounter("katran_de.server.running", 0);
}

DirectEncapServerStats DirectEncapServerApi::getStatsImpl() {
  std::lock_guard<std::mutex> lock(mutex_);
  DirectEncapServerStats stats;
  if (!deServer_) {
    XLOG(ERR) << "Katran DirectEncap Server is not initialized";
    return stats;
  }
  stats.so_stats = deServer_->getSoStats();
  return stats;
}

void DirectEncapServerApi::checkKillswitch() {
  auto* evb = evbThread_.getEventBase();
  evb->runImmediatelyOrRunInEventBaseThread([this, evb, stopped = stopped_] {
    evb->runAfterDelay(
        [this, stopped] {
          if (*stopped) {
            return;
          }
          if (rolloutEnabled(rolloutCheck_, /*valueOnError=*/true)) {
            checkKillswitch();
            return;
          }
          XLOG(INFO)
              << "Server killswitch disabled the feature, uninstalling...";
          *stopped = true;
          uninstallImpl();
          facebook::fb303::fbData->setCounter("katran_de.server.enabled", 0);
        },
        kRolloutCheckIntervalMs);
  });
}

} // namespace katran_de
