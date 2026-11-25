#pragma once

#include <folly/executors/FunctionScheduler.h>
#include <folly/io/async/AsyncTimeout.h>
#include <folly/io/async/EventBase.h>
#include <proxygen/lib/stats/BaseStats.h>

#include "katran/kde/core/BaseDirectEncap.h"

namespace katran_tpr {

class KdeStatsPoller : public folly::AsyncTimeout {
 public:
  KdeStatsPoller(
      BaseDirectEncap* kde,
      folly::EventBase* evb,
      const std::string& statsNamePrefix);
  ~KdeStatsPoller() override;

  void shutdown();

  folly::Expected<folly::Unit, std::system_error> runStatsPoller();

 private:
  void timeoutExpired() noexcept override;

  void updateStatsPeriodically();

  void setStaticStats();

  BaseDirectEncap* kde_;
  folly::EventBase* evb_;
  std::atomic<bool> shutdown_{false};
  std::string statsNamePrefix_;

  std::optional<kde_stats> prevSoStats_{std::nullopt};
  std::optional<kde_tc_stats> prevTcStats_{std::nullopt};

  proxygen::BaseStats::TLTimeseries clientEncapPackets_;
  proxygen::BaseStats::TLTimeseries clientEncapBytes_;
  proxygen::BaseStats::TLTimeseries clientEncapBytesPayload_;
  proxygen::BaseStats::TLTimeseries clientConnsEncapped_;
  proxygen::BaseStats::TLTimeseries clientOptSent_;
  proxygen::BaseStats::TLTimeseries clientOptReceived_;
  proxygen::BaseStats::TLTimeseries clientRetransDetected_;
  proxygen::BaseStats::TLTimeseries clientSOErrors_;
  proxygen::BaseStats::TLTimeseries clientSOErrorNatMissing_;
  proxygen::BaseStats::TLTimeseries clientErrorTupleStore_;
  proxygen::BaseStats::TLTimeseries clientTCErrors_;
  proxygen::BaseStats::TLTimeseries clientTCErrorNatReplace_;

  proxygen::BaseStats::TLTimeseries serverOptSent_;
  proxygen::BaseStats::TLTimeseries serverNatOptSent_;
  proxygen::BaseStats::TLTimeseries serverRetransSynack_;
  proxygen::BaseStats::TLTimeseries serverDirectIpBlackhole_;
  proxygen::BaseStats::TLTimeseries serverErrors_;
  proxygen::BaseStats::TLTimeseries serverErrorSysCalls_;
  proxygen::BaseStats::TLTimeseries serverErrorWriteOpt_;
  proxygen::BaseStats::TLTimeseries serverErrorSetso_;
  proxygen::BaseStats::TLTimeseries serverErrorSetcb_;
  proxygen::BaseStats::TLTimeseries serverErrorUnsetCb_;
  proxygen::BaseStats::TLTimeseries serverErrorLoadHdr_;
  proxygen::BaseStats::TLTimeseries serverErrorReserve_;
  proxygen::BaseStats::TLTimeseries serverErrorNoSavedSyn_;
  proxygen::BaseStats::TLTimeseries serverErrorSynackMapUpdate_;

  // TODO(shah256): add vip filter counters for server
  std::vector<proxygen::BaseStats::TLTimeseries> serverRxZonesAcc_;
  std::vector<proxygen::BaseStats::TLTimeseries> serverRxZonesRej_;
  proxygen::BaseStats::TLTimeseries serverRxZoneV1_;
  proxygen::BaseStats::TLTimeseries serverRxZoneUnknownAcc_;
  proxygen::BaseStats::TLTimeseries serverRxZoneUnknownRej_;
};

} // namespace katran_tpr
