#include "katran/kde/core/KdeStatsPoller.h"

#include <katran/kde/core/ClientDirectEncap.h>
#include <katran/kde/core/KdeBpfUtil.h>
#include <katran/kde/core/ServerDirectEncap.h>
#include "common/stats/Stats.h"
#include "fb303/ServiceData.h"
#include "fb303/ThreadCachedServiceData.h"

using facebook::fb303::SUM;

namespace {
constexpr int kTenSecondsInMs = 10000; // sec in msec
} // namespace

namespace katran_tpr {

KdeStatsPoller::KdeStatsPoller(
    BaseDirectEncap* kde,
    folly::EventBase* evb,
    const std::string& statsNamePrefix)
    : AsyncTimeout(evb),
      kde_(kde),
      evb_(evb),
      statsNamePrefix_(statsNamePrefix),
      clientEncapPackets_(statsNamePrefix + ".client.encap_pckts", SUM),
      clientEncapBytes_(statsNamePrefix + ".client.encap_bytes", SUM),
      clientEncapBytesPayload_(
          statsNamePrefix + ".client.encap_bytes_payload",
          SUM),
      clientConnsEncapped_(statsNamePrefix + ".client.conns_encapped", SUM),
      clientOptSent_(statsNamePrefix + ".client.opt_sent", SUM),
      clientOptReceived_(statsNamePrefix + ".client.opt_received", SUM),
      clientRetransDetected_(statsNamePrefix + ".client.retrans_detected", SUM),
      clientSOErrors_(statsNamePrefix + ".client.so_errors", SUM),
      clientSOErrorNatMissing_(
          statsNamePrefix + ".client.error.so_missing_nat",
          SUM),
      clientErrorTupleStore_(
          statsNamePrefix + ".client.error.tuple_store",
          SUM),
      clientTCErrors_(statsNamePrefix + ".client.tc_errors", SUM),
      clientTCErrorNatReplace_(
          statsNamePrefix + ".client.error.tc_replace_nat",
          SUM),
      /* server */
      serverOptSent_(statsNamePrefix + ".server.opt_sent", SUM),
      serverNatOptSent_(statsNamePrefix + ".server.nat.opt_sent", SUM),
      serverRetransSynack_(statsNamePrefix + ".server.retrans_synack", SUM),
      serverDirectIpBlackhole_(
          statsNamePrefix + ".server.directip.blackhole",
          SUM),
      serverErrors_(statsNamePrefix + ".server.errors", SUM),
      serverErrorSysCalls_(statsNamePrefix + ".server.error.syscalls", SUM),
      serverErrorWriteOpt_(statsNamePrefix + ".server.error.write_opt", SUM),
      serverErrorSetso_(statsNamePrefix + ".server.error.setso", SUM),
      serverErrorSetcb_(statsNamePrefix + ".server.error.set_cb", SUM),
      serverErrorUnsetCb_(statsNamePrefix + ".server.error.unset_cb", SUM),
      serverErrorLoadHdr_(statsNamePrefix + ".server.error.load_hdr", SUM),
      serverErrorReserve_(statsNamePrefix + ".server.error.reserve", SUM),
      serverErrorNoSavedSyn_(
          statsNamePrefix + ".server.error.no_saved_syn",
          SUM),
      serverErrorSynackMapUpdate_(
          statsNamePrefix + ".server.error.synack_map_update",
          SUM),
      serverRxZoneV1_(statsNamePrefix + ".server.rx_zone.v1", SUM),
      serverRxZoneUnknownAcc_(
          statsNamePrefix + ".server.rx_zone.unknown.acc",
          SUM),
      serverRxZoneUnknownRej_(
          statsNamePrefix + ".server.rx_zone.unknown.rej",
          SUM) {
  CHECK(kde);
  CHECK(evb);
  for (kde_zone_map zone : kde_->zoneMap()) {
    serverRxZonesAcc_.emplace_back(
        statsNamePrefix + ".server.rx_zone." + zone.zone_name + ".acc", SUM);
    serverRxZonesRej_.emplace_back(
        statsNamePrefix + ".server.rx_zone." + zone.zone_name + ".rej", SUM);
  }
}

KdeStatsPoller::~KdeStatsPoller() {
  shutdown();
}

void KdeStatsPoller::shutdown() {
  if (shutdown_) {
    return;
  }
  shutdown_ = true;
  evb_->runImmediatelyOrRunInEventBaseThreadAndWait(
      [this]() { cancelTimeout(); });
  VLOG(2) << "KDE stats poller is shutting down..";
}

folly::Expected<folly::Unit, std::system_error>
KdeStatsPoller::runStatsPoller() {
  setStaticStats();
  updateStatsPeriodically();
  evb_->runImmediatelyOrRunInEventBaseThreadAndWait(
      [this]() { scheduleTimeout(kTenSecondsInMs); });
  VLOG(2) << "KDE stats poller successfully initialized and is running";
  return folly::Unit();
}

void KdeStatsPoller::timeoutExpired() noexcept {
  if (shutdown_) {
    return;
  }
  updateStatsPeriodically();
  scheduleTimeout(kTenSecondsInMs);
}

void KdeStatsPoller::updateStatsPeriodically() {
  if (shutdown_) {
    return;
  }

  bool clientMode = (kde_->getDirectEncapMode() == DirectEncapMode::CLIENT);

  auto newSoStats = kde_->getSoStats();
  if (prevSoStats_) {
    auto diffSoStats = KdeBpfUtil::diffSoStats(newSoStats, *prevSoStats_);
    if (clientMode) {
      clientOptSent_.add(diffSoStats.client_opt_set);
      clientOptReceived_.add(diffSoStats.client_opt_received);
      clientRetransDetected_.add(diffSoStats.client_retrans);
      clientSOErrors_.add(
          diffSoStats.error_sys_calls + diffSoStats.client_error_write_opt +
          diffSoStats.client_error_nat_missing);
      clientErrorTupleStore_.add(diffSoStats.client_error_tuple_store);
      clientSOErrorNatMissing_.add(diffSoStats.client_error_nat_missing);
    } else {
      serverErrors_.add(KdeBpfUtil::sumServerErrors(diffSoStats));
      serverErrorSysCalls_.add(diffSoStats.error_sys_calls);
      serverErrorWriteOpt_.add(diffSoStats.server_error_write_opt);
      serverErrorSetso_.add(diffSoStats.server_error_setso);
      serverErrorSetcb_.add(diffSoStats.server_error_set_cb);
      serverErrorUnsetCb_.add(diffSoStats.server_error_unset_cb);
      serverErrorLoadHdr_.add(diffSoStats.server_error_load_hdr);
      serverErrorReserve_.add(diffSoStats.server_error_reserve);
      serverErrorNoSavedSyn_.add(diffSoStats.server_error_no_saved_syn);
      serverErrorSynackMapUpdate_.add(
          diffSoStats.server_error_synack_map_update);

      serverOptSent_.add(diffSoStats.server_opt_set);
      serverNatOptSent_.add(diffSoStats.server_nat_opt_set);
      serverRetransSynack_.add(diffSoStats.server_retrans_synack);
      serverDirectIpBlackhole_.add(diffSoStats.server_directip_blackhole);
      serverRxZoneV1_.add(diffSoStats.server_rx_zone_v1);
      for (size_t i = 0; i < serverRxZonesAcc_.size(); i++) {
        serverRxZonesAcc_[i].add(diffSoStats.server_rx_zone[i].acc);
        serverRxZonesRej_[i].add(diffSoStats.server_rx_zone[i].rej);
      }
      serverRxZoneUnknownAcc_.add(diffSoStats.server_rx_zone_unknown_acc);
      serverRxZoneUnknownRej_.add(diffSoStats.server_rx_zone_unknown_rej);
    }
  }
  prevSoStats_ = newSoStats;

  if (clientMode) {
    auto clientKde = dynamic_cast<ClientDirectEncap*>(kde_);
    if (clientKde) {
      if (clientKde->hostMode()) {
        // A gauge, so computed from the running totals, not the diffs. Signed:
        // per-CPU counters are summed non-atomically, so removed can briefly
        // exceed stored.
        facebook::fb303::fbData->setCounter(
            statsNamePrefix_ + ".client.tuple_live",
            static_cast<int64_t>(newSoStats.client_tuple_stored) -
                static_cast<int64_t>(newSoStats.client_tuple_removed));
      }
      auto newTcStats = clientKde->getTcStats();
      if (prevTcStats_) {
        auto diffTcStats = KdeBpfUtil::diffTcStats(newTcStats, *prevTcStats_);
        clientEncapPackets_.add(diffTcStats.encap_ok);
        clientTCErrors_.add(
            diffTcStats.error_sys_calls + diffTcStats.encap_fail +
            diffTcStats.nat_replace_fail);
        clientTCErrorNatReplace_.add(diffTcStats.nat_replace_fail);
        clientEncapBytes_.add(diffTcStats.encap_bytes);
        clientEncapBytesPayload_.add(diffTcStats.encap_payload_bytes);
        clientConnsEncapped_.add(diffTcStats.conns_encapped);
      }
      prevTcStats_ = newTcStats;
    }
  }
}

void KdeStatsPoller::setStaticStats() {
  if (kde_->getDirectEncapMode() == DirectEncapMode::CLIENT) {
    auto clientKde = dynamic_cast<ClientDirectEncap*>(kde_);
    CHECK(clientKde);
    facebook::fb303::fbData->setCounter(
        statsNamePrefix_ + ".client.zone." + clientKde->clientZoneStr(), 1);
  } else {
    auto serverKde = dynamic_cast<ServerDirectEncap*>(kde_);
    CHECK(serverKde);
    for (const auto& name : serverKde->zoneNames(serverKde->serverZones())) {
      facebook::fb303::fbData->setCounter(
          statsNamePrefix_ + ".server.zones." + name, 1);
    }
  }
}

} // namespace katran_tpr
