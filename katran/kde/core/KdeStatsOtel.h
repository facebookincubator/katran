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

#include <atomic>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <system_error>

#include <folly/Expected.h>
#include <folly/Unit.h>
#include <folly/io/async/AsyncTimeout.h>
#include <folly/io/async/EventBase.h>
#include "opentelemetry/exporters/otlp/otlp_http_metric_exporter_options.h" // @manual=fbsource//third-party/opentelemetry-cpp:exporters
#include "opentelemetry/metrics/observer_result.h" // @manual=fbsource//third-party/opentelemetry-cpp:api

#include "katran/kde/core/BaseDirectEncap.h"

namespace katran_tpr {

struct KdeOtelOptions {
  KdeOtelOptions();

  bool validate() const;

  opentelemetry::exporter::otlp::OtlpHttpMetricExporterOptions exporterOptions;
  std::map<std::string, std::string> resourceAttributes;
};

// Polls KDE BPF counters and exports deltas as OpenTelemetry metrics.
class KdeStatsOtel : public folly::AsyncTimeout {
 public:
  static void initGlobal(const KdeOtelOptions& options);
  static void shutdownGlobal();
  static bool isInitialized();

  KdeStatsOtel(BaseDirectEncap* kde, folly::EventBase* evb);
  ~KdeStatsOtel() override;

  void shutdown();

  folly::Expected<folly::Unit, std::system_error> runStatsPoller();

 private:
  void timeoutExpired() noexcept override;

  void updateStatsPeriodically();
  void setStaticDimensions();

  // Called by the OTel SDK on every export to read the tuple_live gauge.
  static void observeTupleLive(
      opentelemetry::metrics::ObserverResult result,
      void* self);

  BaseDirectEncap* kde_;
  folly::EventBase* evb_;
  std::atomic<bool> shutdown_{false};

  // Guards the dimensions below, which observeTupleLive reads on the OTel
  // export thread.
  std::mutex dimensionsMutex_;
  std::string serviceName_{"kde"};
  std::string hostName_;
  std::string role_;
  std::string zone_;

  std::optional<kde_stats> prevSoStats_{std::nullopt};
  std::optional<kde_tc_stats> prevTcStats_{std::nullopt};
};

} // namespace katran_tpr
