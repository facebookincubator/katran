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

#include "katran/kde/core/KdeStatsOtel.h"

#include <unistd.h>
#include <chrono>
#include <memory>
#include <mutex>

#include <glog/logging.h>
#include <katran/kde/core/ClientDirectEncap.h>
#include <katran/kde/core/KdeBpfUtil.h>
#include <katran/kde/core/ServerDirectEncap.h>
#include "opentelemetry/exporters/otlp/otlp_http_metric_exporter_factory.h" // @manual=fbsource//third-party/opentelemetry-cpp:exporters
#include "opentelemetry/exporters/otlp/otlp_http_metric_exporter_options.h" // @manual=fbsource//third-party/opentelemetry-cpp:exporters
#include "opentelemetry/sdk/metrics/export/periodic_exporting_metric_reader.h" // @manual=fbsource//third-party/opentelemetry-cpp:sdk
#include "opentelemetry/sdk/metrics/export/periodic_exporting_metric_reader_options.h" // @manual=fbsource//third-party/opentelemetry-cpp:sdk
#include "opentelemetry/sdk/metrics/meter_provider.h" // @manual=fbsource//third-party/opentelemetry-cpp:sdk
#include "opentelemetry/sdk/metrics/meter_provider_factory.h" // @manual=fbsource//third-party/opentelemetry-cpp:sdk
#include "opentelemetry/sdk/metrics/view/view_registry_factory.h" // @manual=fbsource//third-party/opentelemetry-cpp:sdk
#include "opentelemetry/sdk/resource/resource.h" // @manual=fbsource//third-party/opentelemetry-cpp:sdk

namespace metrics_api = opentelemetry::metrics;
namespace metrics_sdk = opentelemetry::sdk::metrics;
namespace sdkotlp = opentelemetry::v1::exporter::otlp;
namespace sdkresource = opentelemetry::v1::sdk::resource;

namespace {

constexpr int kTenSecondsInMs = 10000;
constexpr auto kMeterName = "katran.kde";
constexpr auto kMeterVersion = "1.0.0";

struct KdeOtelState {
  std::shared_ptr<metrics_sdk::MeterProvider> provider;
  opentelemetry::nostd::shared_ptr<metrics_api::Meter> meter;

  opentelemetry::nostd::unique_ptr<metrics_api::Counter<uint64_t>>
      clientOptSent;
  opentelemetry::nostd::unique_ptr<metrics_api::Counter<uint64_t>>
      clientOptReceived;
  opentelemetry::nostd::unique_ptr<metrics_api::Counter<uint64_t>>
      clientRetransDetected;
  opentelemetry::nostd::unique_ptr<metrics_api::Counter<uint64_t>>
      clientSoErrors;
  opentelemetry::nostd::unique_ptr<metrics_api::Counter<uint64_t>>
      clientEncapPackets;
  opentelemetry::nostd::unique_ptr<metrics_api::Counter<uint64_t>>
      clientEncapBytes;
  opentelemetry::nostd::unique_ptr<metrics_api::Counter<uint64_t>>
      clientEncapBytesPayload;
  opentelemetry::nostd::unique_ptr<metrics_api::Counter<uint64_t>>
      clientConnsEncapped;
  opentelemetry::nostd::unique_ptr<metrics_api::Counter<uint64_t>>
      clientTcErrors;
  opentelemetry::nostd::unique_ptr<metrics_api::Counter<uint64_t>>
      clientErrorTupleStore;
  // The vendored SDK is built with ABI v1, which has no synchronous gauge.
  opentelemetry::nostd::shared_ptr<metrics_api::ObservableInstrument>
      clientTupleLive;

  opentelemetry::nostd::unique_ptr<metrics_api::Counter<uint64_t>>
      serverOptSent;
  opentelemetry::nostd::unique_ptr<metrics_api::Counter<uint64_t>> serverErrors;
  opentelemetry::nostd::unique_ptr<metrics_api::Counter<uint64_t>>
      serverErrorSyscalls;
  opentelemetry::nostd::unique_ptr<metrics_api::Counter<uint64_t>>
      serverErrorWriteOpt;
  opentelemetry::nostd::unique_ptr<metrics_api::Counter<uint64_t>>
      serverErrorSetso;
  opentelemetry::nostd::unique_ptr<metrics_api::Counter<uint64_t>>
      serverErrorSetCb;
  opentelemetry::nostd::unique_ptr<metrics_api::Counter<uint64_t>>
      serverErrorUnsetCb;
  opentelemetry::nostd::unique_ptr<metrics_api::Counter<uint64_t>>
      serverErrorLoadHdr;
  opentelemetry::nostd::unique_ptr<metrics_api::Counter<uint64_t>>
      serverErrorReserve;
  opentelemetry::nostd::unique_ptr<metrics_api::Counter<uint64_t>>
      serverErrorNoSavedSyn;

  opentelemetry::nostd::unique_ptr<metrics_api::Counter<uint64_t>>
      serverRxZoneV1;
  // one per named zone, created from the zone map in the KdeStatsOtel ctor
  std::vector<opentelemetry::nostd::unique_ptr<metrics_api::Counter<uint64_t>>>
      serverRxZonesAcc;
  std::vector<opentelemetry::nostd::unique_ptr<metrics_api::Counter<uint64_t>>>
      serverRxZonesRej;
  opentelemetry::nostd::unique_ptr<metrics_api::Counter<uint64_t>>
      serverRxZoneUnknownAcc;
  opentelemetry::nostd::unique_ptr<metrics_api::Counter<uint64_t>>
      serverRxZoneUnknownRej;
};

// NOLINTNEXTLINE(facebook-avoid-non-const-global-variables)
std::mutex g_stateMutex;
// NOLINTNEXTLINE(facebook-avoid-non-const-global-variables)
std::unique_ptr<KdeOtelState> g_state;

std::string getHostname() {
  std::array<char, 256> hostnameBuffer{};
  if (gethostname(hostnameBuffer.data(), hostnameBuffer.size()) == 0) {
    hostnameBuffer.back() = '\0';
    return hostnameBuffer.data();
  }
  return "unknown";
}

} // namespace

namespace katran_tpr {

KdeOtelOptions::KdeOtelOptions() {
  exporterOptions.aggregation_temporality =
      sdkotlp::PreferredAggregationTemporality::kDelta;
}

bool KdeOtelOptions::validate() const {
  if (exporterOptions.url.empty()) {
    LOG(ERROR) << "OpenTelemetry metrics endpoint is empty";
    return false;
  }
  return true;
}

void KdeStatsOtel::initGlobal(const KdeOtelOptions& options) {
  std::lock_guard<std::mutex> lock(g_stateMutex);
  if (g_state) {
    LOG(WARNING) << "KdeStatsOtel::initGlobal() called more than once, "
                 << "ignoring";
    return;
  }
  sdkresource::ResourceAttributes resourceAttributes;
  for (const auto& [name, value] : options.resourceAttributes) {
    resourceAttributes.emplace(name, value);
  }
  auto resource = sdkresource::Resource::Create(resourceAttributes);

  auto exporter =
      sdkotlp::OtlpHttpMetricExporterFactory::Create(options.exporterOptions);

  metrics_sdk::PeriodicExportingMetricReaderOptions readerOptions;
  readerOptions.export_interval_millis = std::chrono::milliseconds(10000);
  readerOptions.export_timeout_millis = std::chrono::milliseconds(5000);
  auto reader = std::make_unique<metrics_sdk::PeriodicExportingMetricReader>(
      std::move(exporter), readerOptions);

  auto viewRegistry = metrics_sdk::ViewRegistryFactory::Create();
  auto provider = metrics_sdk::MeterProviderFactory::Create(
      std::move(viewRegistry), resource);
  provider->AddMetricReader(std::move(reader));

  auto meter = provider->GetMeter(kMeterName, kMeterVersion);

  auto state = std::make_unique<KdeOtelState>();
  state->provider = std::move(provider);
  state->meter = meter;

  state->clientOptSent = meter->CreateUInt64Counter("kde_client_opt_sent");
  state->clientOptReceived =
      meter->CreateUInt64Counter("kde_client_opt_received");
  state->clientRetransDetected =
      meter->CreateUInt64Counter("kde_client_retrans_detected");
  state->clientSoErrors = meter->CreateUInt64Counter("kde_client_so_errors");
  state->clientEncapPackets =
      meter->CreateUInt64Counter("kde_client_encap_pckts");
  state->clientEncapBytes =
      meter->CreateUInt64Counter("kde_client_encap_bytes");
  state->clientEncapBytesPayload =
      meter->CreateUInt64Counter("kde_client_encap_bytes_payload");
  state->clientConnsEncapped =
      meter->CreateUInt64Counter("kde_client_conns_encapped");
  state->clientTcErrors = meter->CreateUInt64Counter("kde_client_tc_errors");
  state->clientErrorTupleStore =
      meter->CreateUInt64Counter("kde_client_error_tuple_store");
  state->clientTupleLive =
      meter->CreateInt64ObservableGauge("kde_client_tuple_live");

  state->serverOptSent = meter->CreateUInt64Counter("kde_server_opt_sent");
  state->serverErrors = meter->CreateUInt64Counter("kde_server_errors");
  state->serverErrorSyscalls =
      meter->CreateUInt64Counter("kde_server_error_syscalls");
  state->serverErrorWriteOpt =
      meter->CreateUInt64Counter("kde_server_error_write_opt");
  state->serverErrorSetso =
      meter->CreateUInt64Counter("kde_server_error_setso");
  state->serverErrorSetCb =
      meter->CreateUInt64Counter("kde_server_error_set_cb");
  state->serverErrorUnsetCb =
      meter->CreateUInt64Counter("kde_server_error_unset_cb");
  state->serverErrorLoadHdr =
      meter->CreateUInt64Counter("kde_server_error_load_hdr");
  state->serverErrorReserve =
      meter->CreateUInt64Counter("kde_server_error_reserve");
  state->serverErrorNoSavedSyn =
      meter->CreateUInt64Counter("kde_server_error_no_saved_syn");

  state->serverRxZoneV1 = meter->CreateUInt64Counter("kde_server_rx_zone_v1");
  state->serverRxZoneUnknownAcc =
      meter->CreateUInt64Counter("kde_server_rx_zone_unknown_acc");
  state->serverRxZoneUnknownRej =
      meter->CreateUInt64Counter("kde_server_rx_zone_unknown_rej");

  g_state = std::move(state);
  LOG(INFO) << "KDE OTEL metrics initialized successfully";
}

void KdeStatsOtel::shutdownGlobal() {
  std::lock_guard<std::mutex> lock(g_stateMutex);
  if (!g_state) {
    return;
  }
  if (g_state->provider) {
    LOG(INFO) << "Shutting down KDE OTEL metrics...";
    (void)g_state->provider->ForceFlush(std::chrono::milliseconds(5000));
    // MeterProvider destruction performs SDK shutdown. Calling Shutdown()
    // explicitly and then resetting the provider emits an "Shutdown can be
    // invoked only once" warning from the OTel SDK.
    g_state->provider.reset();
  }
  g_state.reset();
}

bool KdeStatsOtel::isInitialized() {
  std::lock_guard<std::mutex> lock(g_stateMutex);
  return g_state != nullptr;
}

KdeStatsOtel::KdeStatsOtel(BaseDirectEncap* kde, folly::EventBase* evb)
    : AsyncTimeout(evb), kde_(kde), evb_(evb), hostName_(getHostname()) {
  CHECK(kde);
  CHECK(evb);
  // zone names come from the KDE instance, so these counters are created here
  // rather than in initGlobal(); one KDE per process creates them once
  std::lock_guard<std::mutex> lock(g_stateMutex);
  if (g_state && g_state->serverRxZonesAcc.empty()) {
    for (const auto& zone : kde_->zoneMap()) {
      g_state->serverRxZonesAcc.push_back(g_state->meter->CreateUInt64Counter(
          std::string("kde_server_rx_zone_") + zone.zone_name + "_acc"));
      g_state->serverRxZonesRej.push_back(g_state->meter->CreateUInt64Counter(
          std::string("kde_server_rx_zone_") + zone.zone_name + "_rej"));
    }
  }
}

KdeStatsOtel::~KdeStatsOtel() {
  shutdown();
}

void KdeStatsOtel::shutdown() {
  if (shutdown_) {
    return;
  }
  shutdown_ = true;
  evb_->runImmediatelyOrRunInEventBaseThreadAndWait(
      [this]() { cancelTimeout(); });
  {
    // No-op if the callback was never added (not in host mode).
    std::lock_guard<std::mutex> lock(g_stateMutex);
    if (g_state && g_state->clientTupleLive) {
      g_state->clientTupleLive->RemoveCallback(
          &KdeStatsOtel::observeTupleLive, this);
    }
  }
  VLOG(2) << "KDE OTEL stats poller is shutting down";
}

folly::Expected<folly::Unit, std::system_error> KdeStatsOtel::runStatsPoller() {
  setStaticDimensions();
  updateStatsPeriodically();
  evb_->runImmediatelyOrRunInEventBaseThreadAndWait(
      [this]() { scheduleTimeout(kTenSecondsInMs); });
  VLOG(2) << "KDE OTEL stats poller successfully initialized and is running";
  return folly::Unit();
}

void KdeStatsOtel::timeoutExpired() noexcept {
  if (shutdown_) {
    return;
  }
  updateStatsPeriodically();
  scheduleTimeout(kTenSecondsInMs);
}

void KdeStatsOtel::setStaticDimensions() {
  bool hostMode = false;
  {
    std::lock_guard<std::mutex> lock(dimensionsMutex_);
    if (kde_->getDirectEncapMode() == DirectEncapMode::CLIENT) {
      role_ = "client";
      auto* clientKde = dynamic_cast<ClientDirectEncap*>(kde_);
      CHECK(clientKde);
      zone_ = clientKde->clientZoneStr();
      hostMode = clientKde->hostMode();
    } else {
      role_ = "server";
      auto* serverKde = dynamic_cast<ServerDirectEncap*>(kde_);
      CHECK(serverKde);
      zone_ = serverKde->serverZonesStr();
    }
  }
  // Must not hold dimensionsMutex_ here: the SDK calls observeTupleLive
  // under its callback lock, and observeTupleLive takes dimensionsMutex_.
  if (hostMode) {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    if (g_state && g_state->clientTupleLive) {
      g_state->clientTupleLive->AddCallback(
          &KdeStatsOtel::observeTupleLive, this);
    }
  }
}

void KdeStatsOtel::updateStatsPeriodically() {
  if (shutdown_) {
    return;
  }

  const bool clientMode =
      (kde_->getDirectEncapMode() == DirectEncapMode::CLIENT);

  const auto addIfNonZero = [this](
                                const opentelemetry::nostd::unique_ptr<
                                    metrics_api::Counter<uint64_t>>& counter,
                                uint64_t value) {
    if (value == 0 || !counter) {
      return;
    }
    counter->Add(
        value,
        {
            {"service_name", serviceName_},
            {"host_name", hostName_},
            {"role", role_},
            {"zone", zone_},
        });
  };

  auto newSoStats = kde_->getSoStats();
  std::optional<kde_tc_stats> newTcStats;
  if (clientMode) {
    if (auto* clientKde = dynamic_cast<ClientDirectEncap*>(kde_)) {
      newTcStats = clientKde->getTcStats();
    }
  }

  std::lock_guard<std::mutex> lock(g_stateMutex);
  if (prevSoStats_ && g_state) {
    auto diffSoStats = KdeBpfUtil::diffSoStats(newSoStats, *prevSoStats_);
    if (clientMode) {
      addIfNonZero(g_state->clientOptSent, diffSoStats.client_opt_set);
      addIfNonZero(g_state->clientOptReceived, diffSoStats.client_opt_received);
      addIfNonZero(g_state->clientRetransDetected, diffSoStats.client_retrans);
      addIfNonZero(
          g_state->clientSoErrors,
          diffSoStats.error_sys_calls + diffSoStats.client_error_write_opt);
      addIfNonZero(
          g_state->clientErrorTupleStore, diffSoStats.client_error_tuple_store);
    } else {
      addIfNonZero(
          g_state->serverErrors, KdeBpfUtil::sumServerErrors(diffSoStats));
      addIfNonZero(g_state->serverErrorSyscalls, diffSoStats.error_sys_calls);
      addIfNonZero(
          g_state->serverErrorWriteOpt, diffSoStats.server_error_write_opt);
      addIfNonZero(g_state->serverErrorSetso, diffSoStats.server_error_setso);
      addIfNonZero(g_state->serverErrorSetCb, diffSoStats.server_error_set_cb);
      addIfNonZero(
          g_state->serverErrorUnsetCb, diffSoStats.server_error_unset_cb);
      addIfNonZero(
          g_state->serverErrorLoadHdr, diffSoStats.server_error_load_hdr);
      addIfNonZero(
          g_state->serverErrorReserve, diffSoStats.server_error_reserve);
      addIfNonZero(
          g_state->serverErrorNoSavedSyn,
          diffSoStats.server_error_no_saved_syn);
      addIfNonZero(g_state->serverOptSent, diffSoStats.server_opt_set);
      addIfNonZero(g_state->serverRxZoneV1, diffSoStats.server_rx_zone_v1);
      for (size_t i = 0; i < g_state->serverRxZonesAcc.size(); i++) {
        addIfNonZero(
            g_state->serverRxZonesAcc[i], diffSoStats.server_rx_zone[i].acc);
        addIfNonZero(
            g_state->serverRxZonesRej[i], diffSoStats.server_rx_zone[i].rej);
      }
      addIfNonZero(
          g_state->serverRxZoneUnknownAcc,
          diffSoStats.server_rx_zone_unknown_acc);
      addIfNonZero(
          g_state->serverRxZoneUnknownRej,
          diffSoStats.server_rx_zone_unknown_rej);
    }
  }
  prevSoStats_ = newSoStats;

  if (newTcStats) {
    if (prevTcStats_ && g_state) {
      auto diffTcStats = KdeBpfUtil::diffTcStats(*newTcStats, *prevTcStats_);
      addIfNonZero(g_state->clientEncapPackets, diffTcStats.encap_ok);
      addIfNonZero(
          g_state->clientTcErrors,
          diffTcStats.error_sys_calls + diffTcStats.encap_fail);
      addIfNonZero(g_state->clientEncapBytes, diffTcStats.encap_bytes);
      addIfNonZero(
          g_state->clientEncapBytesPayload, diffTcStats.encap_payload_bytes);
      addIfNonZero(g_state->clientConnsEncapped, diffTcStats.conns_encapped);
    }
    prevTcStats_ = *newTcStats;
  }
}

void KdeStatsOtel::observeTupleLive(
    opentelemetry::metrics::ObserverResult result,
    void* self) {
  auto* stats = static_cast<KdeStatsOtel*>(self);
  auto soStats = stats->kde_->getSoStats();
  auto& observer = opentelemetry::nostd::get<
      opentelemetry::nostd::shared_ptr<metrics_api::ObserverResultT<int64_t>>>(
      result);
  std::lock_guard<std::mutex> lock(stats->dimensionsMutex_);
  // A gauge, so computed from the running totals, not diffs. Signed: per-CPU
  // counters are summed non-atomically, so removed can briefly exceed stored.
  observer->Observe(
      static_cast<int64_t>(soStats.client_tuple_stored) -
          static_cast<int64_t>(soStats.client_tuple_removed),
      {
          {"service_name", stats->serviceName_},
          {"host_name", stats->hostName_},
          {"role", stats->role_},
          {"zone", stats->zone_},
      });
}

} // namespace katran_tpr
