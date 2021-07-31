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

#include <chrono>
#include <iostream>
#include <thread>

#include <folly/Conv.h>
#include <folly/File.h>
#include <folly/FileUtil.h>
#include <folly/Range.h>
#include <gflags/gflags.h>

#include "katran/lib/MonitoringStructs.h"
#include "katran/lib/testing/BpfTester.h"
#include "katran/lib/testing/KatranGueOptionalTestFixtures.h"
#include "katran/lib/testing/KatranHCTestFixtures.h"
#include "katran/lib/testing/KatranOptionalTestFixtures.h"
#include "katran/lib/testing/KatranTestProvision.h"
#include "katran/lib/testing/KatranTestUtil.h"

using namespace katran::testing;
using KatranFeatureEnum = katran::KatranFeatureEnum;

#ifndef MAX_VIPS
#define MAX_VIPS 512
#endif

DEFINE_string(pcap_input, "", "path to input pcap file");
DEFINE_string(pcap_output, "", "path to output pcap file");
DEFINE_string(
    monitor_output,
    "/tmp/katran_pcap",
    "output file for katran monitoring");
DEFINE_string(balancer_prog, "./balancer_kern.o", "path to balancer bpf prog");
DEFINE_string(
    reloaded_balancer_prog,
    "",
    "path to balancer bpf prog which would reload main one");
DEFINE_string(healthchecking_prog, "", "path to healthchecking bpf prog");
DEFINE_bool(print_base64, false, "print packets in base64 from pcap file");
DEFINE_bool(test_from_fixtures, false, "run tests on predefined dataset");
DEFINE_bool(perf_testing, false, "run perf tests on predefined dataset");
DEFINE_bool(optional_tests, false, "run optional (kernel specific) tests");
DEFINE_bool(
    optional_counter_tests,
    false,
    "run optional (kernel specific) counter tests");
DEFINE_bool(gue, false, "run GUE tests instead of IPIP ones");
DEFINE_bool(
    tpr,
    false,
    "run tests for TCP Server-Id based routing (TPR) instead of IPIP or GUE ones");
DEFINE_int32(repeat, 1000000, "perf test runs for single packet");
DEFINE_int32(position, -1, "perf test runs for single packet");
DEFINE_bool(iobuf_storage, false, "test iobuf storage for katran monitor");
DEFINE_int32(
    packet_num,
    -1,
    "Pass packet number to run single test, default -1 to run all");
DEFINE_int32(
    install_features_mask,
    0,
    "Bitmask of katran features to install. 1 = SrcRouting, 2 = InlineDecap, "
    "4 = Introspection, 8 = GueEncap, 16 = DirectHealthchecking, "
    "32 = LocalDeliveryOptimization. "
    "e.g. 13 means SrcRouting + Introspection + GueEncap");
DEFINE_int32(
    remove_features_mask,
    0,
    "Bitmask of katran features to install. 1 = SrcRouting, 2 = InlineDecap, "
    "4 = Introspection, 8 = GueEncap, 16 = DirectHealthchecking, "
    "32 = LocalDeliveryOptimization. "
    "e.g. 13 means SrcRouting + Introspection + GueEncap");

void testKatranMonitor(katran::KatranLb& lb) {
  lb.stopKatranMonitor();
  std::this_thread::sleep_for(std::chrono::seconds(1));
  constexpr std::array<katran::monitoring::EventId, 2> events = {
      katran::monitoring::EventId::TCP_NONSYN_LRUMISS,
      katran::monitoring::EventId::PACKET_TOOBIG,
  };

  for (const auto event : events) {
    auto buf = lb.getKatranMonitorEventBuffer(event);
    std::string fname;
    folly::toAppend(FLAGS_monitor_output, "_event_", event, &fname);
    if (buf != nullptr) {
      LOG(INFO) << "buffer length is: " << buf->length();
      auto pcap_file = folly::File(fname.c_str(), O_RDWR | O_CREAT | O_TRUNC);
      auto res = folly::writeFull(pcap_file.fd(), buf->data(), buf->length());
      if (res < 0) {
        LOG(ERROR) << "error while trying to write katran monitor output";
      }
    }
  }
}

void testHcFromFixture(katran::KatranLb& lb, katran::BpfTester& tester) {
  if (lb.getHealthcheckerProgFd() < 0) {
    LOG(INFO) << "Healthchecking not enabled. Skipping HC related tests";
    return;
  }
  tester.resetTestFixtures(
      katran::testing::inputHCTestFixtures,
      katran::testing::outputHCTestFixtures);
  auto ctxs = katran::testing::getInputCtxsForHcTest();
  tester.testClsFromFixture(lb.getHealthcheckerProgFd(), ctxs);
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

void preTestOptionalLbCounters(katran::KatranLb& lb) {
  validateMapSize(lb, "vip_map", 0, katran::kDefaultMaxVips);
  validateMapSize(
      lb, "reals", katran::kDefaultMaxReals, katran::kDefaultMaxReals);
  if (!FLAGS_healthchecking_prog.empty()) {
    validateMapSize(lb, "hc_reals_map", 0, katran::kDefaultMaxReals);
  }
  LOG(INFO) << "Initial testing of counters is complete";
  return;
}

void postTestOptionalLbCounters(katran::KatranLb& lb) {
  validateMapSize(lb, "vip_map", 8, katran::kDefaultMaxVips);
  validateMapSize(
      lb, "reals", katran::kDefaultMaxReals, katran::kDefaultMaxReals);
  if (!FLAGS_healthchecking_prog.empty()) {
    validateMapSize(lb, "hc_reals_map", 3, katran::kDefaultMaxReals);
  }
  LOG(INFO) << "Followup testing of counters is complete";
}

void testLbCounters(katran::KatranLb& lb, KatranTestParam& testParam) {
  katran::VipKey vip;
  vip.address = "10.200.1.1";
  vip.port = kVipPort;
  vip.proto = kTcp;
  LOG(INFO) << "Testing counter's sanity. Printing on errors only";
  for (auto& vipCounter : testParam.perVipCounters) {
    auto vipStats = lb.getStatsForVip(vip);
    if ((vipStats.v1 != testParam.expectedTotalPktsForVip(vipCounter.first)) ||
        (vipStats.v2 != testParam.expectedTotalBytesForVip(vipCounter.first))) {
      VLOG(2) << "pckts: " << vipStats.v1 << ", bytes: " << vipStats.v2;
      LOG(ERROR) << "per Vip counter is incorrect for vip:" << vip.address;
    }
  }
  auto stats = lb.getLruStats();
  if ((stats.v1 != testParam.expectedTotalPkts()) ||
      (stats.v2 != testParam.expectedTotalLruMisses())) {
    VLOG(2) << "Total pckts: " << stats.v1 << ", LRU misses: " << stats.v2;
    LOG(ERROR) << "LRU counter is incorrect";
  }
  stats = lb.getLruMissStats();
  if ((stats.v1 != testParam.expectedTotalTcpSyns()) ||
      (stats.v2 != testParam.expectedTotalTcpNonSynLruMisses())) {
    VLOG(2) << "TCP syns: " << stats.v1 << " TCP non-syns: " << stats.v2;
    LOG(ERROR) << "per pckt type LRU miss counter is incorrect";
  }
  stats = lb.getLruFallbackStats();
  if (stats.v1 != testParam.expectedTotalLruFallbackHits()) {
    VLOG(2) << "FallbackLRU hits: " << stats.v1;
    LOG(ERROR) << "LRU fallback counter is incorrect";
  }
  stats = lb.getQuicRoutingStats();
  if (stats.v1 != testParam.expectedQuicRoutingWithCh() ||
      stats.v2 != testParam.expectedQuicRoutingWithCid()) {
    LOG(ERROR) << "Counters for QUIC packets routed with CH: " << stats.v1
               << ",  with connection-id: " << stats.v2;
    LOG(ERROR) << "Counters for routing of QUIC packets is wrong.";
  }
  stats = lb.getQuicCidVersionStats();
  if (stats.v1 != testParam.expectedQuicCidV1Counts() ||
      stats.v2 != testParam.expectedQuicCidV2Counts()) {
    LOG(ERROR) << "QUIC CID version counters v1 " << stats.v1 << " v2 "
               << stats.v2;
    LOG(ERROR) << "Counters for QUIC versions are wrong";
  }
  stats = lb.getQuicCidDropStats();
  if (stats.v1 != testParam.expectedQuicCidDropsReal0Counts() ||
      stats.v2 != testParam.expectedQuicCidDropsNoRealCounts()) {
    LOG(ERROR) << "QUIC CID drop counters v1 " << stats.v1 << " v2 "
               << stats.v2;
    LOG(ERROR) << "Counters for QUIC drops are wrong";
  }
  stats = lb.getTcpServerIdRoutingStats();
  if (stats.v2 != testParam.expectedTcpServerIdRoutingCounts() ||
      stats.v1 != testParam.expectedTcpServerIdRoutingFallbackCounts()) {
    LOG(ERROR) << "Counters for TCP server-id routing with CH (v1): " << stats.v1
               << ", with server-id (v2): " << stats.v2;
    LOG(ERROR) << "Counters for TCP server-id based routing are wrong";
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
    }
  }
  auto lb_stats = lb.getKatranLbStats();
  if (lb_stats.bpfFailedCalls != testParam.expectedTotalFailedBpfCalls()) {
    VLOG(2) << "failed bpf calls: " << lb_stats.bpfFailedCalls;
    LOG(INFO) << "incorrect stats about katran library internals: "
              << "number of failed bpf syscalls is non zero";
  }
  if (lb_stats.addrValidationFailed !=
      testParam.expectedTotalAddressValidations()) {
    VLOG(2) << "failed ip address validations: "
            << lb_stats.addrValidationFailed;
    LOG(INFO) << "incorrect stats about katran library internals: "
              << "number of failed ip address validations is non zero";
  }

  LOG(INFO) << "Testing of counters is complete";
  return;
}

void runTestsFromFixture(
    katran::KatranLb& lb,
    katran::BpfTester& tester,
    KatranTestParam& testParam) {
  prepareLbData(lb);
  tester.resetTestFixtures(testParam.inputData, testParam.outputData);
  auto prog_fd = lb.getKatranProgFd();
  tester.setBpfProgFd(prog_fd);
  tester.testFromFixture();
  testLbCounters(lb, testParam);
  if (FLAGS_optional_counter_tests) {
    postTestOptionalLbCounters(lb);
  }
  testSimulator(lb);
  if (FLAGS_iobuf_storage) {
    LOG(INFO) << "Test katran monitor";
    testKatranMonitor(lb);
  }
  testHcFromFixture(lb, tester);
  if (FLAGS_optional_tests) {
    prepareOptionalLbData(lb);
    LOG(INFO) << "Running optional tests. they could fail if requirements "
              << "are not satisfied";
    if (FLAGS_gue) {
      tester.resetTestFixtures(
          katran::testing::inputGueOptionalTestFixtures,
          katran::testing::outputGueOptionalTestFixtures);
    } else {
      tester.resetTestFixtures(
          katran::testing::inputOptionalTestFixtures,
          katran::testing::outputOptionalTestFixtures);
    }
    tester.testFromFixture();
    testOptionalLbCounters(lb, testParam);
  }
}

std::string toString(katran::KatranFeatureEnum feature) {
  switch (feature) {
    case KatranFeatureEnum::SrcRouting:
      return "SrcRouting";
    case KatranFeatureEnum::InlineDecap:
      return "InlineDecap";
    case KatranFeatureEnum::Introspection:
      return "Introspection";
    case KatranFeatureEnum::GueEncap:
      return "GueEncap";
    case KatranFeatureEnum::DirectHealthchecking:
      return "DirectHealthchecking";
    case KatranFeatureEnum::LocalDeliveryOptimization:
      return "LocalDeliveryOptimization";
    case KatranFeatureEnum::FlowDebug:
      return "FlowDebug";
  }
  folly::assume_unreachable();
}

static const std::vector<KatranFeatureEnum> kAllFeatures = {
    KatranFeatureEnum::SrcRouting,
    KatranFeatureEnum::InlineDecap,
    KatranFeatureEnum::Introspection,
    KatranFeatureEnum::GueEncap,
    KatranFeatureEnum::DirectHealthchecking,
    KatranFeatureEnum::LocalDeliveryOptimization,
    KatranFeatureEnum::FlowDebug,
};

void listFeatures(katran::KatranLb& lb) {
  for (auto feature : kAllFeatures) {
    if (lb.hasFeature(feature)) {
      LOG(INFO) << "feature: " << toString(feature);
    }
  }
}

void testInstallAndRemoveFeatures(katran::KatranLb& lb) {
  if (FLAGS_install_features_mask > 0) {
    for (auto feature : kAllFeatures) {
      if (FLAGS_install_features_mask & static_cast<int>(feature)) {
        if (lb.installFeature(feature, FLAGS_reloaded_balancer_prog)) {
          LOG(INFO) << "feature installed: " << toString(feature);
        } else {
          LOG(ERROR) << "feature install failed: " << toString(feature);
        }
      }
    }
  }

  if (FLAGS_remove_features_mask > 0) {
    for (auto feature : kAllFeatures) {
      if (FLAGS_remove_features_mask & static_cast<int>(feature)) {
        if (lb.removeFeature(feature, FLAGS_reloaded_balancer_prog)) {
          LOG(INFO) << "feature removed: " << toString(feature);
        } else {
          LOG(ERROR) << "feature remove failed: " << toString(feature);
        }
      }
    }
  }
}

KatranTestParam getTestParam() {
  if (FLAGS_gue) {
    return createDefaultTestParam(TestMode::GUE);
  } else if (FLAGS_tpr) {
    return createTPRTestParam();
  } else {
    return createDefaultTestParam(TestMode::DEFAULT);
  }
}

int main(int argc, char** argv) {
  gflags::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  FLAGS_logtostderr = 1;
  katran::TesterConfig config;
  auto testParam = getTestParam();
  config.inputFileName = FLAGS_pcap_input;
  config.outputFileName = FLAGS_pcap_output;
  config.inputData = testParam.inputData;
  config.outputData = testParam.outputData;

  if (FLAGS_packet_num >= 0) {
    config.singleTestRunPacketNumber_ = FLAGS_packet_num;
  }
  katran::BpfTester tester(config);
  if (FLAGS_print_base64) {
    if (FLAGS_pcap_input.empty()) {
      std::cout << "pcap_input is not specified! exiting";
      return 1;
    }
    tester.printPcktBase64();
    return 0;
  }
  katran::KatranMonitorConfig kmconfig;
  kmconfig.path = FLAGS_monitor_output;
  if (FLAGS_iobuf_storage) {
    kmconfig.storage = katran::PcapStorageFormat::IOBUF;
    kmconfig.bufferSize = k1Mbyte;
  }
  katran::KatranConfig kconfig{kMainInterface,
                               kV4TunInterface,
                               kV6TunInterface,
                               FLAGS_balancer_prog,
                               FLAGS_healthchecking_prog,
                               kDefaultMac,
                               kDefaultPriority,
                               kNoExternalMap,
                               kDefaultKatranPos};

  kconfig.enableHc = FLAGS_healthchecking_prog.empty() ? false : true;
  kconfig.monitorConfig = kmconfig;
  kconfig.katranSrcV4 = "10.0.13.37";
  kconfig.katranSrcV6 = "fc00:2307::1337";
  kconfig.localMac = kLocalMac;
  kconfig.maxVips = MAX_VIPS;

  katran::KatranLb lb(kconfig);
  lb.loadBpfProgs();
  listFeatures(lb);
  auto balancer_prog_fd = lb.getKatranProgFd();
  if (FLAGS_optional_counter_tests) {
    preTestOptionalLbCounters(lb);
  }
  tester.setBpfProgFd(balancer_prog_fd);
  if (FLAGS_test_from_fixtures) {
    runTestsFromFixture(lb, tester, testParam);
    if (FLAGS_install_features_mask > 0 || FLAGS_remove_features_mask > 0) {
      // install/remove features will reload prog if provided, therefore
      // reloading again is redundant
      testInstallAndRemoveFeatures(lb);
      runTestsFromFixture(lb, tester, testParam);
    } else if (!FLAGS_reloaded_balancer_prog.empty()) {
      auto res = lb.reloadBalancerProg(FLAGS_reloaded_balancer_prog);
      if (!res) {
        LOG(INFO) << "cannot reload balancer program";
        return 1;
      }
      listFeatures(lb);
      runTestsFromFixture(lb, tester, testParam);
    }
    return 0;
  }
  prepareLbData(lb);
  if (!FLAGS_pcap_input.empty()) {
    tester.testPcktsFromPcap();
    return 0;
  } else if (FLAGS_perf_testing) {
    // for perf tests to work katran must be compiled w -DINLINE_DECAP
    preparePerfTestingLbData(lb);
    tester.testPerfFromFixture(FLAGS_repeat, FLAGS_position);
  }
  return 0;
}
