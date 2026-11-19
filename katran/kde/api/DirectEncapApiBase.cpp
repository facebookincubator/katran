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

#include "katran/kde/api/DirectEncapApiBase.h"
#include <cstdlib>

namespace katran_de {

bool rolloutEnabled(const std::function<bool()>& check, bool valueOnError) {
  try {
    return check();
  } catch (const std::exception& e) {
    LOG(ERROR) << "Failed to evaluate KDE rollout check: " << e.what();
    return valueOnError;
  }
}

bool DirectEncapApiBase::initialized() {
  return getImpl() != nullptr;
}

bool DirectEncapApiBase::installWithParamsImpl(const KdeInstallParams& params) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (initialized()) {
    LOG(ERROR) << "DirectEncap is already initialized";
    return false;
  }
  if (!initImpl(params)) {
    return false;
  }
  rolloutCheck_ = params.rolloutCheck;

  // if detached mode is enabled, we don't need to do anything else
  if (params.detach) {
    return true;
  }

  CHECK(evbThread_.getEventBase());
  if (params.otelStats) {
    const auto* otelEndpoint = std::getenv("OTEL_EXPORTER_OTLP_ENDPOINT");
    if (otelEndpoint == nullptr || *otelEndpoint == '\0') {
      LOG(ERROR) << "--otel requires OTEL_EXPORTER_OTLP_ENDPOINT to be set";
      return false;
    }
    katran_tpr::KdeStatsOtel::initGlobal(otelEndpoint);
    kdeStatsOtel_ = std::make_unique<katran_tpr::KdeStatsOtel>(
        getImpl(), evbThread_.getEventBase());
    auto res = kdeStatsOtel_->runStatsPoller();
    if (res.hasError()) {
      LOG(ERROR) << "Error initializing OTEL stats poller: "
                 << res.error().what();
    }
  } else {
    kdeStatsPoller_ = std::make_unique<katran_tpr::KdeStatsPoller>(
        getImpl(), evbThread_.getEventBase(), "katran_de");
    auto res = kdeStatsPoller_->runStatsPoller();
    if (res.hasError()) {
      LOG(ERROR) << "Error initializing fb303 stats poller: "
                 << res.error().what();
    }
  }
  return true;
}

} // namespace katran_de
