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

#include "katran/lib/testing/KatranTestUtil.h"
#include "katran/lib/testing/KatranGueTestFixtures.h"
#include "katran/lib/testing/KatranIcmpTooBigTestFixtures.h"
#include "katran/lib/testing/KatranTPRTestFixtures.h"
#include "katran/lib/testing/KatranTestFixtures.h"
#include "katran/lib/testing/KatranUdpFlowMigrationTestFixtures.h"
#include "katran/lib/testing/KatranUdpStableRtTestFixtures.h"
#include "katran/lib/testing/KatranXPopDecapTestFixtures.h"

#include <folly/File.h>
#include <folly/FileUtil.h>

namespace katran {
namespace testing {

bool testSimulator(katran::KatranLb& lb) {
  bool success{true};
  // udp, v4 vip v4 real
  auto real = lb.getRealForFlow(katran::KatranFlow{
      .src = "172.16.0.1",
      .dst = "10.200.1.1",
      .srcPort = 31337,
      .dstPort = 80,
      .proto = kUdp,
  });
  if (real != "10.0.0.2") {
    VLOG(2) << "real: " << real;
    LOG(INFO) << "simulation is incorrect for v4 real and v4 udp vip";
    success = false;
  }
  // tcp, v4 vip v4 real
  real = lb.getRealForFlow(katran::KatranFlow{
      .src = "172.16.0.1",
      .dst = "10.200.1.1",
      .srcPort = 31337,
      .dstPort = 80,
      .proto = kTcp,
  });
  if (real != "10.0.0.2") {
    VLOG(2) << "real: " << real;
    LOG(INFO) << "simulation is incorrect for v4 real and v4 tcp vip";
    success = false;
  }
  // tcp, v4 vip v6 real
  real = lb.getRealForFlow(katran::KatranFlow{
      .src = "172.16.0.1",
      .dst = "10.200.1.3",
      .srcPort = 31337,
      .dstPort = 80,
      .proto = kTcp,
  });
  if (real != "fc00::2") {
    VLOG(2) << "real: " << real;
    LOG(INFO) << "simulation is incorrect for v6 real and v4 tcp vip";
    success = false;
  }
  // tcp, v6 vip v6 real
  real = lb.getRealForFlow(katran::KatranFlow{
      .src = "fc00:2::1",
      .dst = "fc00:1::1",
      .srcPort = 31337,
      .dstPort = 80,
      .proto = kTcp,
  });
  if (real != "fc00::3") {
    VLOG(2) << "real: " << real;
    LOG(INFO) << "simulation is incorrect for v6 real and v6 tcp vip";
    success = false;
  }
  // non existing vip
  real = lb.getRealForFlow(katran::KatranFlow{
      .src = "fc00:2::1",
      .dst = "fc00:1::2",
      .srcPort = 31337,
      .dstPort = 80,
      .proto = kTcp,
  });
  if (!real.empty()) {
    VLOG(2) << "real: " << real;
    LOG(INFO) << "incorrect real for non existing vip";
    success = false;
  }
  // malformed flow #1
  real = lb.getRealForFlow(katran::KatranFlow{
      .src = "10.0.0.1",
      .dst = "fc00:1::1",
      .srcPort = 31337,
      .dstPort = 80,
      .proto = kTcp,
  });
  if (!real.empty()) {
    VLOG(2) << "real: " << real;
    LOG(INFO) << "incorrect real for malformed flow #1";
    success = false;
  }
  // malformed flow #2
  real = lb.getRealForFlow(katran::KatranFlow{
      .src = "aaaa",
      .dst = "bbbb",
      .srcPort = 31337,
      .dstPort = 80,
      .proto = kTcp,
  });
  if (!real.empty()) {
    VLOG(2) << "real: " << real;
    LOG(INFO) << "incorrect real for malformed flow #2";
    success = false;
  }
  return success;
}

KatranTestParam createDefaultTestParam(TestMode testMode) {
  katran::VipKey vip;
  vip.address = "10.200.1.1";
  vip.port = kVipPort;
  vip.proto = kTcp;
  KatranTestParam testParam = {
      .mode = testMode,
      .testData = testMode == TestMode::GUE ? katran::testing::gueTestFixtures
                                            : katran::testing::testFixtures,
      .expectedCounters =
          {
              {KatranTestCounters::TOTAL_PKTS, 25},
              {KatranTestCounters::LRU_MISSES, 11},
              {KatranTestCounters::TCP_SYNS, 2},
              {KatranTestCounters::NON_SYN_LRU_MISSES, 6},
              {KatranTestCounters::LRU_FALLBACK_HITS, 19},
              {KatranTestCounters::QUIC_ROUTING_WITH_CH, 7},
              {KatranTestCounters::QUIC_ROUTING_WITH_CID, 4},
              {KatranTestCounters::QUIC_CID_V1, 4},
              {KatranTestCounters::QUIC_CID_V2, 2},
              {KatranTestCounters::QUIC_CID_DROPS_REAL_0, 0},
              {KatranTestCounters::QUIC_CID_DROPS_NO_REAL, 2},
              {KatranTestCounters::TOTAL_FAILED_BPF_CALLS, 0},
              {KatranTestCounters::TOTAL_ADDRESS_VALIDATION_FAILED, 0},
              // optional counters
              {KatranTestCounters::ICMP_V4_COUNTS, 1},
              {KatranTestCounters::ICMP_V6_COUNTS, 1},
              {KatranTestCounters::SRC_ROUTING_PKTS_LOCAL, 2},
              {KatranTestCounters::SRC_ROUTING_PKTS_REMOTE, 6},
              {KatranTestCounters::INLINE_DECAP_PKTS, 4},
              // unused
              {KatranTestCounters::TCP_SERVER_ID_ROUNTING, 0},
              {KatranTestCounters::TCP_SERVER_ID_ROUTING_FALLBACK_CH, 0},
          },
      .perVipCounters = {{vip, std::pair<uint64_t, uint64_t>(4, 248)}}};
  return testParam;
}

KatranTestParam createTPRTestParam() {
  katran::VipKey vip;
  vip.address = "10.200.1.1";
  vip.port = kVipPort;
  vip.proto = kTcp;
  KatranTestParam testParam = {
      .mode = TestMode::TPR,
      .testData = katran::testing::tprTestFixtures,
      .expectedCounters =
          {
              {KatranTestCounters::TOTAL_PKTS, 17},
              {KatranTestCounters::LRU_MISSES, 3},
              {KatranTestCounters::TCP_SYNS, 1},
              {KatranTestCounters::NON_SYN_LRU_MISSES, 2},
              {KatranTestCounters::LRU_FALLBACK_HITS, 17},
              {KatranTestCounters::TCP_SERVER_ID_ROUNTING, 8},
              {KatranTestCounters::TCP_SERVER_ID_ROUTING_FALLBACK_CH, 8},
              {KatranTestCounters::TOTAL_FAILED_BPF_CALLS, 0},
              {KatranTestCounters::TOTAL_ADDRESS_VALIDATION_FAILED, 0},
          },
      .perVipCounters = {{vip, std::pair<uint64_t, uint64_t>(4, 244)}}};
  return testParam;
}

KatranTestParam createUdpStableRtTestParam() {
  katran::VipKey vip;
  vip.address = "fc00:1::9";
  vip.port = kVipPort;
  vip.proto = kUdp;
  KatranTestParam testParam = {
      .mode = TestMode::GUE,
      .testData = katran::testing::udpStableRtFixtures,
      .expectedCounters =
          {
              {KatranTestCounters::TOTAL_PKTS, 5},
              {KatranTestCounters::STABLE_RT_CH_ROUTING, 2},
              {KatranTestCounters::STABLE_RT_CID_ROUTING, 3},
              {KatranTestCounters::STABLE_RT_CID_INVALID_SERVER_ID, 0},
              {KatranTestCounters::STABLE_RT_CID_UNKNOWN_REAL_DROPPED, 0},
              {KatranTestCounters::STABLE_RT_INVALID_PACKET_TYPE, 0},
          },
      .perVipCounters = {{vip, std::pair<uint64_t, uint64_t>(4, 244)}}};
  return testParam;
}

KatranTestParam createXPopDecapTestParam() {
  katran::VipKey vip;
  vip.address = "10.200.1.1";
  vip.port = kVipPort;
  vip.proto = kTcp;
  KatranTestParam testParam = {
      .mode = TestMode::GUE,
      .testData = katran::testing::xPopDecapTestFixtures,
      .expectedCounters =
          {
              {KatranTestCounters::INLINE_DECAP_PKTS, 5},
              {KatranTestCounters::XPOP_DECAP_SUCCESSFUL, 3},
          },
      .perVipCounters = {{vip, std::pair<uint64_t, uint64_t>(4, 244)}}};
  return testParam;
}

KatranTestParam createUdpFlowMigrationTestParam(
    const std::vector<::katran::PacketAttributes>& fixture,
    uint8_t totalInvalidations) {
  katran::VipKey vip;
  vip.address = "10.200.1.1";
  vip.port = kVipPort;
  vip.proto = kUdp;
  KatranTestParam testParam = {
      .mode = TestMode::GUE,
      .testData = fixture,
      .expectedCounters =
          {
              {KatranTestCounters::TOTAL_PKTS, 4},
              {KatranTestCounters::UDP_FLOW_MIGRATION_STATS,
               totalInvalidations},
          },
      .perVipCounters = {{vip, std::pair<uint64_t, uint64_t>(3, 180)}}};
  return testParam;
}

KatranTestParam createIcmpTooBigTestParam() {
  katran::VipKey vip;
  vip.address = "10.200.1.1";
  vip.port = kVipPort;
  vip.proto = kTcp;
  KatranTestParam testParam = {
      .mode = TestMode::GUE,
      .testData = katran::testing::icmpTooBigTestFixtures,
      .expectedCounters =
          {
              {KatranTestCounters::TOTAL_PKTS, 14},
              {KatranTestCounters::LRU_MISSES, 14},
              {KatranTestCounters::LRU_FALLBACK_HITS, 14},
              {KatranTestCounters::TOTAL_FAILED_BPF_CALLS, 0},
              {KatranTestCounters::ICMP_V4_COUNTS, 1},
              {KatranTestCounters::ICMP_V6_COUNTS, 1},
              {KatranTestCounters::INLINE_DECAP_PKTS, 2},
          },
      .perVipCounters = {{vip, std::pair<uint64_t, uint64_t>(4, 248)}}};
  return testParam;
}

void testOptionalLbCounters(katran::KatranLb& lb, KatranTestParam& testParam) {
  LOG(INFO) << "Testing optional counter's sanity";
  auto stats = lb.getIcmpTooBigStats();
  if (stats.v1 != testParam.expectedIcmpV4Counts() ||
      stats.v2 != testParam.expectedIcmpV6Counts()) {
    VLOG(2) << "icmpV4 hits: " << stats.v1 << " icmpv6 hits:" << stats.v2;
    LOG(INFO) << "icmp packet too big counter is incorrect";
  }
  stats = lb.getSrcRoutingStats();
  if (stats.v1 != testParam.expectedSrcRoutingPktsLocal() ||
      stats.v2 != testParam.expectedSrcRoutingPktsRemote()) {
    VLOG(2) << "lpm src. local pckts: " << stats.v1 << " remote:" << stats.v2;
    LOG(INFO) << "source based routing counter is incorrect";
  }
  stats = lb.getInlineDecapStats();
  if (stats.v1 != testParam.expectedInlineDecapPkts()) {
    VLOG(2) << "inline decapsulated pckts: " << stats.v1;
    LOG(INFO) << "inline decapsulated packet's counter is incorrect";
  }
  LOG(INFO) << "KatranMonitor stats (only for -DKATRAN_INTROSPECTION)";
  auto monitor_stats = lb.getKatranMonitorStats();
  LOG(INFO) << "limit: " << monitor_stats.limit
            << " amount: " << monitor_stats.amount;
  LOG(INFO) << "Testing of optional counters is complete";
}

bool testStableRtCounters(katran::KatranLb& lb, KatranTestParam& testParam) {
  LOG(INFO) << "Testing optional counter's sanity";
  bool counters_ok = true;
  auto stats = lb.getUdpStableRoutingStats();
  if (stats.ch_routed != testParam.expectedUdpStableRoutingWithCh()) {
    VLOG(2) << "CH routed pckts: " << stats.ch_routed;
    LOG(INFO) << "CH routed packet's counter is incorrect";
    counters_ok = false;
  }
  if (stats.cid_routed != testParam.expectedUdpStableRoutingWithCid()) {
    VLOG(2) << "SID routed pckts: " << stats.cid_routed;
    LOG(INFO) << "SID routed packet's counter is incorrect";
    counters_ok = false;
  }
  if (stats.cid_invalid_server_id !=
      testParam.expectedUdpStableRoutingInvalidSid()) {
    VLOG(2) << "cid_invalid_server_id pckts: " << stats.cid_invalid_server_id;
    LOG(INFO) << "cid_invalid_server_id counter is incorrect";
    counters_ok = false;
  }
  if (stats.cid_unknown_real_dropped !=
      testParam.expectedUdpStableRoutingUnknownReals()) {
    VLOG(2) << "cid_unknown_real_dropped pckts: "
            << stats.cid_unknown_real_dropped;
    LOG(INFO) << "cid_unknown_real_dropped counter is incorrect";
    counters_ok = false;
  }
  if (stats.invalid_packet_type !=
      testParam.expectedUdpStableRoutingInvalidPacketType()) {
    VLOG(2) << "invalid_packet_type pckts: " << stats.cid_unknown_real_dropped;
    LOG(INFO) << "invalid_packet_type counter is incorrect";
    counters_ok = false;
  }
  LOG(INFO) << "Stable Routing stats verified";
  return counters_ok;
}

bool testXPopDecapCounters(katran::KatranLb& lb, KatranTestParam& testParam) {
  LOG(INFO) << "Testing cross pop decapsulation sanity";
  bool counters_ok = true;

  // Check general inline decap stats
  auto stats = lb.getInlineDecapStats();
  if (stats.v1 != testParam.expectedInlineDecapPkts()) {
    LOG(INFO) << "inline decapsulated packet's counter is incorrect: "
              << stats.v1;
    counters_ok = false;
  }

  // Check successful xpop decap counter
  auto successfulStats = lb.getXPopDecapSuccessfulStats();
  if (successfulStats.v1 != testParam.expectedXPopDecapSuccessful()) {
    VLOG(2) << "xpop decap successful: " << successfulStats.v1;
    LOG(INFO) << "xpop decap successful counter is incorrect: "
              << successfulStats.v1;
    counters_ok = false;
  }

  LOG(INFO) << "Testing of cross pop decapsulation counters is complete";
  return counters_ok;
}

bool testUdpFlowMigrationCounters(
    katran::KatranLb& lb,
    KatranTestParam& testParam) {
  LOG(INFO) << "Testing UDP flow migration sanity";
  bool counters_ok = true;

  // Check UDP flow migration invalidation counter
  auto stats = lb.getUdpFlowMigrationStats();
  if (stats.v1 != testParam.expectedUdpFlowMigrationInvalidation()) {
    VLOG(2) << "UDP flow migration invalidations: " << stats.v1;
    LOG(INFO) << "UDP flow migration invalidation counter is incorrect: "
              << stats.v1 << " vs expected: "
              << testParam.expectedUdpFlowMigrationInvalidation();
    counters_ok = false;
  }

  return counters_ok;
}

void validateMapSize(
    katran::KatranLb& lb,
    const std::string& map_name,
    int expected_current,
    int expected_max) {
  auto map_stats = lb.getBpfMapStats(map_name);
  VLOG(3) << map_name << ": " << map_stats.currentEntries << "/"
          << map_stats.maxEntries;
  if (expected_max != map_stats.maxEntries) {
    LOG(INFO) << map_name
              << ": max size is incorrect: " << map_stats.maxEntries;
  }
  if (expected_current != map_stats.currentEntries) {
    LOG(INFO) << map_name
              << ": current size is incorrect: " << map_stats.currentEntries;
  }
}

void preTestOptionalLbCounters(
    katran::KatranLb& lb,
    const std::string& healthcheckingProg) {
  validateMapSize(lb, "vip_map", 0, katran::kDefaultMaxVips);
  validateMapSize(
      lb, "reals", katran::kDefaultMaxReals, katran::kDefaultMaxReals);
  if (!healthcheckingProg.empty()) {
    validateMapSize(lb, "hc_reals_map", 0, katran::kDefaultMaxReals);
  }
  LOG(INFO) << "Initial testing of counters is complete";
  return;
}

void postTestOptionalLbCounters(
    katran::KatranLb& lb,
    const std::string& healthcheckingProg) {
  validateMapSize(lb, "vip_map", 8, katran::kDefaultMaxVips);
  validateMapSize(
      lb, "reals", katran::kDefaultMaxReals, katran::kDefaultMaxReals);
  if (!healthcheckingProg.empty()) {
    validateMapSize(lb, "hc_reals_map", 3, katran::kDefaultMaxReals);
  }
  LOG(INFO) << "Followup testing of counters is complete";
}

bool testLbCounters(katran::KatranLb& lb, KatranTestParam& testParam) {
  katran::VipKey vip;
  vip.address = "10.200.1.1";
  vip.port = kVipPort;
  vip.proto = kTcp;
  LOG(INFO) << "Testing counter's sanity. Printing on errors only";
  bool counters_ok = true;
  for (auto& vipCounter : testParam.perVipCounters) {
    auto vipStats = lb.getStatsForVip(vip);
    if ((vipStats.v1 != testParam.expectedTotalPktsForVip(vipCounter.first)) ||
        (vipStats.v2 != testParam.expectedTotalBytesForVip(vipCounter.first))) {
      VLOG(2) << "pckts: " << vipStats.v1 << ", bytes: " << vipStats.v2;
      LOG(ERROR) << "per Vip counter is incorrect for vip:" << vip.address;
      counters_ok = false;
    }
  }
  auto stats = lb.getLruStats();
  if ((stats.v1 != testParam.expectedTotalPkts()) ||
      (stats.v2 != testParam.expectedTotalLruMisses())) {
    VLOG(2) << "Total pckts: " << stats.v1 << ", LRU misses: " << stats.v2;
    LOG(ERROR) << "LRU counter is incorrect";
    counters_ok = false;
  }
  stats = lb.getLruMissStats();
  if ((stats.v1 != testParam.expectedTotalTcpSyns()) ||
      (stats.v2 != testParam.expectedTotalTcpNonSynLruMisses())) {
    VLOG(2) << "TCP syns: " << stats.v1 << " TCP non-syns: " << stats.v2;
    LOG(ERROR) << "per pckt type LRU miss counter is incorrect";
    // counters_ok = false; //TODO: enable after fixing the sanity counters
  }
  stats = lb.getLruFallbackStats();
  if (stats.v1 != testParam.expectedTotalLruFallbackHits()) {
    VLOG(2) << "FallbackLRU hits: " << stats.v1;
    LOG(ERROR) << "LRU fallback counter is incorrect";
    // counters_ok = false;
  }
  auto tprStats = lb.getTcpServerIdRoutingStats();
  if (tprStats.sid_routed != testParam.expectedTcpServerIdRoutingCounts() ||
      tprStats.ch_routed !=
          testParam.expectedTcpServerIdRoutingFallbackCounts()) {
    LOG(ERROR) << "Counters for TCP server-id routing with CH (v1): "
               << tprStats.ch_routed
               << ", with server-id (v2): " << tprStats.sid_routed;
    LOG(ERROR) << "Counters for TCP server-id based routing are wrong";
    // counters_ok = false;
  }
  auto quicStats = lb.getLbQuicPacketsStats();
  if (quicStats.ch_routed != testParam.expectedQuicRoutingWithCh() ||
      quicStats.cid_routed != testParam.expectedQuicRoutingWithCid()) {
    LOG(ERROR) << "Counters for QUIC packets routed with CH: "
               << quicStats.ch_routed
               << ",  with connection-id: " << quicStats.cid_routed;
    LOG(ERROR) << "Counters for routing of QUIC packets is wrong.";
    // counters_ok = false;
  }
  if (quicStats.cid_v1 != testParam.expectedQuicCidV1Counts() ||
      quicStats.cid_v2 != testParam.expectedQuicCidV2Counts()) {
    LOG(ERROR) << "QUIC CID version counters v1 " << stats.v1 << " v2 "
               << stats.v2;
    LOG(ERROR) << "Counters for QUIC versions are wrong";
    counters_ok = false;
  }
  if (quicStats.cid_invalid_server_id !=
          testParam.expectedQuicCidDropsReal0Counts() ||
      quicStats.cid_unknown_real_dropped !=
          testParam.expectedQuicCidDropsNoRealCounts()) {
    LOG(ERROR) << "QUIC CID drop counters v1 " << stats.v1 << " v2 "
               << stats.v2;
    LOG(ERROR) << "Counters for QUIC drops are wrong";
    // counters_ok = false;
  }
  auto realStats = testParam.expectedRealStats();
  for (int i = 0; i < kReals.size(); i++) {
    auto real = kReals[i];
    auto id = lb.getIndexForReal(real);
    if (id < 0) {
      LOG(INFO) << "Real does not exists: " << real;
      continue;
    }
    stats = lb.getRealStats(id);
    auto expected_stats = realStats[i];
    if (stats.v1 != expected_stats.v1 || stats.v2 != expected_stats.v2) {
      VLOG(2) << "stats for real: " << real << " v1: " << stats.v1
              << " v2: " << stats.v2;
      LOG(INFO) << "incorrect stats for real: " << real;
      LOG(INFO) << "Expected to be incorrect w/ non default build flags";
      // counters_ok = false;
    }
  }
  auto lb_stats = lb.getKatranLbStats();
  if (lb_stats.bpfFailedCalls != testParam.expectedTotalFailedBpfCalls()) {
    VLOG(2) << "failed bpf calls: " << lb_stats.bpfFailedCalls;
    LOG(INFO) << "incorrect stats about katran library internals: "
              << "number of failed bpf syscalls is non zero";
    counters_ok = false;
  }
  if (lb_stats.addrValidationFailed !=
      testParam.expectedTotalAddressValidations()) {
    VLOG(2) << "failed ip address validations: "
            << lb_stats.addrValidationFailed;
    LOG(INFO) << "incorrect stats about katran library internals: "
              << "number of failed ip address validations is non zero";
    counters_ok = false;
  }

  LOG(INFO) << "Testing of counters is complete";
  return counters_ok;
}

/**
 * Custom test function for ICMP Too Big counters
 * This function tests both basic load balancer counters and
 * ICMP Too Big specific counters that are relevant for this test case
 */
bool testIcmpTooBigCounters(katran::KatranLb& lb, KatranTestParam& testParam) {
  LOG(INFO) << "Testing ICMP Too Big counter's sanity";
  bool counters_ok = true;

  // Test basic load balancer counters
  auto stats = lb.getLruStats();
  if ((stats.v1 != testParam.expectedTotalPkts()) ||
      (stats.v2 != testParam.expectedTotalLruMisses())) {
    LOG(ERROR) << "Total pckts: " << stats.v1 << ", LRU misses: " << stats.v2;
    LOG(ERROR) << "LRU counter is incorrect";
    counters_ok = false;
  }

  // Test ICMP Too Big specific counters
  auto icmpStats = lb.getIcmpTooBigStats();
  if (icmpStats.v1 != testParam.expectedIcmpV4Counts() ||
      icmpStats.v2 != testParam.expectedIcmpV6Counts()) {
    LOG(ERROR) << "icmpV4 hits: " << icmpStats.v1
               << " icmpv6 hits:" << icmpStats.v2;
    LOG(ERROR) << "ICMP packet too big counter is incorrect";
    counters_ok = false;
  }

  // Test inline decapsulation stats which are relevant for ICMP Too Big
  auto inlineDecapStats = lb.getInlineDecapStats();
  if (inlineDecapStats.v1 != testParam.expectedInlineDecapPkts()) {
    LOG(ERROR) << "inline decapsulated pckts: " << inlineDecapStats.v1;
    LOG(ERROR) << "inline decapsulated packet's counter is incorrect";
    counters_ok = false;
  }

  LOG(INFO) << "Testing of ICMP Too Big counters is complete";
  return counters_ok;
}

std::string toString(KatranFeatureEnum feature) {
  switch (feature) {
    case KatranFeatureEnum::SrcRouting:
      return "LPM_SRC";
    case KatranFeatureEnum::InlineDecap:
      return "INLINE_DECAP";
    case KatranFeatureEnum::Introspection:
      return "INTROSPECTION";
    case KatranFeatureEnum::GueEncap:
      return "GUE_ENCAP";
    case KatranFeatureEnum::DirectHealthchecking:
      return "DIRECT_HC";
    case KatranFeatureEnum::LocalDeliveryOptimization:
      return "LOCAL_DELIVERY";
    case KatranFeatureEnum::FlowDebug:
      return "FLOW_DEBUG";
    default:
      return "UNKNOWN";
  }
}
} // namespace testing
} // namespace katran
