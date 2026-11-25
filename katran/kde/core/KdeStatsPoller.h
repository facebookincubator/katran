#pragma once

#include <atomic>
#include <optional>
#include <string>
#include <vector>

#include <fb303/ThreadCachedServiceData.h>
#include <folly/io/async/AsyncTimeout.h>
#include <folly/io/async/EventBase.h>

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

  facebook::fb303::MinuteOnlyTimeseriesWrapper clientEncapPackets_;
  facebook::fb303::MinuteOnlyTimeseriesWrapper clientEncapBytes_;
  facebook::fb303::MinuteOnlyTimeseriesWrapper clientEncapBytesPayload_;
  facebook::fb303::MinuteOnlyTimeseriesWrapper clientConnsEncapped_;
  facebook::fb303::MinuteOnlyTimeseriesWrapper clientOptSent_;
  facebook::fb303::MinuteOnlyTimeseriesWrapper clientOptReceived_;
  facebook::fb303::MinuteOnlyTimeseriesWrapper clientRetransDetected_;
  facebook::fb303::MinuteOnlyTimeseriesWrapper clientSOErrors_;
  facebook::fb303::MinuteOnlyTimeseriesWrapper clientSOErrorNatMissing_;
  facebook::fb303::MinuteOnlyTimeseriesWrapper clientErrorTupleStore_;
  facebook::fb303::MinuteOnlyTimeseriesWrapper clientTCErrors_;
  facebook::fb303::MinuteOnlyTimeseriesWrapper clientTCErrorNatReplace_;

  facebook::fb303::MinuteOnlyTimeseriesWrapper serverOptSent_;
  facebook::fb303::MinuteOnlyTimeseriesWrapper serverNatOptSent_;
  facebook::fb303::MinuteOnlyTimeseriesWrapper serverRetransSynack_;
  facebook::fb303::MinuteOnlyTimeseriesWrapper serverDirectIpBlackhole_;
  facebook::fb303::MinuteOnlyTimeseriesWrapper serverErrors_;
  facebook::fb303::MinuteOnlyTimeseriesWrapper serverErrorSysCalls_;
  facebook::fb303::MinuteOnlyTimeseriesWrapper serverErrorWriteOpt_;
  facebook::fb303::MinuteOnlyTimeseriesWrapper serverErrorSetso_;
  facebook::fb303::MinuteOnlyTimeseriesWrapper serverErrorSetcb_;
  facebook::fb303::MinuteOnlyTimeseriesWrapper serverErrorUnsetCb_;
  facebook::fb303::MinuteOnlyTimeseriesWrapper serverErrorLoadHdr_;
  facebook::fb303::MinuteOnlyTimeseriesWrapper serverErrorReserve_;
  facebook::fb303::MinuteOnlyTimeseriesWrapper serverErrorNoSavedSyn_;
  facebook::fb303::MinuteOnlyTimeseriesWrapper serverErrorSynackMapUpdate_;

  // TODO(shah256): add vip filter counters for server
  std::vector<facebook::fb303::MinuteOnlyTimeseriesWrapper> serverRxZonesAcc_;
  std::vector<facebook::fb303::MinuteOnlyTimeseriesWrapper> serverRxZonesRej_;
  facebook::fb303::MinuteOnlyTimeseriesWrapper serverRxZoneV1_;
  facebook::fb303::MinuteOnlyTimeseriesWrapper serverRxZoneUnknownAcc_;
  facebook::fb303::MinuteOnlyTimeseriesWrapper serverRxZoneUnknownRej_;
};

} // namespace katran_tpr
