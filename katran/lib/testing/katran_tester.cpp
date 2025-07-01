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
#include "katran/lib/testing/KatranHCTestFixtures.h"
#include "katran/lib/testing/KatranIcmpTooBigTestFixtures.h"
#include "katran/lib/testing/KatranOptionalTestFixtures.h"
#include "katran/lib/testing/KatranTestProvision.h"
#include "katran/lib/testing/KatranTestUtil.h"
#include "katran/lib/testing/KatranUdpFlowMigrationTestFixtures.h"
#include "katran/lib/testing/KatranUdpStableRtTestFixtures.h"
#include "katran/lib/testing/KatranXPopDecapTestFixtures.h"

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
DEFINE_string(balancer_prog, "./balancer.bpf.o", "path to balancer bpf prog");
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
DEFINE_bool(stable_rt, false, "run UDP Stable Routing tests");
DEFINE_bool(xpop_decap, false, "run cross pop decap tests");
DEFINE_bool(udp_flow_migration, false, "run UDP flow migration tests");
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
  tester.resetTestFixtures(katran::testing::hcTestFixtures);
  auto ctxs = katran::testing::getInputCtxsForHcTest();
  tester.testClsFromFixture(lb.getHealthcheckerProgFd(), ctxs);
}

void runTestsFromFixture(
    katran::KatranLb& lb,
    katran::BpfTester& tester,
    KatranTestParam& testParam) {
  prepareLbData(lb);
  prepareVipUninitializedLbData(lb);

  tester.resetTestFixtures(testParam.testData);
  auto prog_fd = lb.getKatranProgFd();
  tester.setBpfProgFd(prog_fd);
  tester.testFromFixture();
  if (!testLbCounters(lb, testParam)) {
    LOG(ERROR) << "counters do not match";
  }
  if (FLAGS_optional_counter_tests) {
    postTestOptionalLbCounters(lb, FLAGS_healthchecking_prog);
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
      tester.resetTestFixtures(katran::testing::icmpTooBigTestFixtures);
    } else {
      tester.resetTestFixtures(katran::testing::optionalTestFixtures);
    }
    tester.testFromFixture();
    testOptionalLbCounters(lb, testParam);
  }
  if (FLAGS_stable_rt) {
    prepareLbDataStableRt(lb);
    tester.resetTestFixtures(katran::testing::udpStableRtFixtures);
    tester.testFromFixture();
    auto udpTestParams = createUdpStableRtTestParam();
    testStableRtCounters(lb, udpTestParams);
  }
  if (FLAGS_xpop_decap) {
    prepareLbDataXpopDecap(lb);
    tester.resetTestFixtures(katran::testing::xPopDecapTestFixtures);
    tester.testFromFixture();
    auto xpopTestParams = createXPopDecapTestParam();
    testXPopDecapCounters(lb, xpopTestParams);
  }
  if (FLAGS_udp_flow_migration) {
    prepareUdpFlowMigrationTestData(lb);
    tester.resetTestFixtures(
        katran::testing::udpFlowMigrationTestFirstFixtures);
    tester.testFromFixture();
    auto udpFlowMigrationParams = createUdpFlowMigrationTestParam(
        katran::testing::udpFlowMigrationTestFirstFixtures, 0);
    testUdpFlowMigrationCounters(lb, udpFlowMigrationParams);

    setDownHostForUdpFlowMigration(lb);

    tester.resetTestFixtures(
        katran::testing::udpFlowMigrationTestSecondFixtures);
    tester.testFromFixture();
    auto udpFlowMigrationParams2 = createUdpFlowMigrationTestParam(
        katran::testing::udpFlowMigrationTestSecondFixtures, 2);
    testUdpFlowMigrationCounters(lb, udpFlowMigrationParams2);
  }
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
  config.testData = testParam.testData;

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
  katran::KatranConfig kconfig{
      kMainInterface,
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

  auto lb = std::make_unique<katran::KatranLb>(
      kconfig, std::make_unique<katran::BpfAdapter>(kconfig.memlockUnlimited));
  lb->loadBpfProgs();
  listFeatures(*lb);
  auto balancer_prog_fd = lb->getKatranProgFd();
  if (FLAGS_optional_counter_tests) {
    preTestOptionalLbCounters(*lb, FLAGS_healthchecking_prog);
  }
  tester.setBpfProgFd(balancer_prog_fd);
  if (FLAGS_test_from_fixtures) {
    runTestsFromFixture(*lb, tester, testParam);
    if (FLAGS_install_features_mask > 0 || FLAGS_remove_features_mask > 0) {
      // install/remove features will reload prog if provided, therefore
      // reloading again is redundant
      testInstallAndRemoveFeatures(*lb);
      runTestsFromFixture(*lb, tester, testParam);
    } else if (!FLAGS_reloaded_balancer_prog.empty()) {
      auto res = lb->reloadBalancerProg(FLAGS_reloaded_balancer_prog);
      if (!res) {
        LOG(INFO) << "cannot reload balancer program";
        return 1;
      }
      listFeatures(*lb);
      runTestsFromFixture(*lb, tester, testParam);
    }
    return 0;
  }
  prepareLbData(*lb);
  if (!FLAGS_pcap_input.empty()) {
    tester.testPcktsFromPcap();
    return 0;
  } else if (FLAGS_perf_testing) {
    // for perf tests to work katran must be compiled w -DINLINE_DECAP
    preparePerfTestingLbData(*lb);
    tester.testPerfFromFixture(FLAGS_repeat, FLAGS_position);
  }
  return 0;
}
