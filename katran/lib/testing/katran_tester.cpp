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
#include <string>
#include <thread>
#include <vector>

#include <folly/File.h>
#include <folly/FileUtil.h>
#include <folly/Range.h>
#include <gflags/gflags.h>

#include "katran/lib/KatranLb.h"
#include "katran/lib/KatranLbStructs.h"
#include "katran/lib/testing/BpfTester.h"
#include "katran/lib/testing/KatranGueOptionalTestFixtures.h"
#include "katran/lib/testing/KatranGueTestFixtures.h"
#include "katran/lib/testing/KatranHCTestFixtures.h"
#include "katran/lib/testing/KatranOptionalTestFixtures.h"
#include "katran/lib/testing/KatranTestFixtures.h"

DEFINE_string(pcap_input, "", "path to input pcap file");
DEFINE_string(pcap_output, "", "path to output pcap file");
DEFINE_string(
    monitor_output,
    "/tmp/katran_pcap",
    "output file for katran monitoring");
DEFINE_string(balancer_prog, "./balancer_kern.o", "path to balancer bpf prog");
DEFINE_string(healthchecking_prog, "", "path to healthchecking bpf prog");
DEFINE_bool(print_base64, false, "print packets in base64 from pcap file");
DEFINE_bool(test_from_fixtures, false, "run tests on predefined dataset");
DEFINE_bool(perf_testing, false, "run perf tests on predefined dataset");
DEFINE_bool(optional_tests, false, "run optional (kernel specific) tests");
DEFINE_bool(optional_counter_tests, false, "run optional (kernel specific) counter tests");
DEFINE_bool(gue, false, "run GUE tests instead of IPIP ones");
DEFINE_int32(repeat, 1000000, "perf test runs for single packet");
DEFINE_int32(position, -1, "perf test runs for single packet");
DEFINE_bool(iobuf_storage, false, "test iobuf storage for katran monitor");

namespace {
const std::string kMainInterface = "lo";
const std::string kV4TunInterface = "lo";
const std::string kV6TunInterface = "lo";
const std::string kNoExternalMap = "";
const std::vector<uint8_t> kDefaultMac = {0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xAF};
const std::vector<uint8_t> kLocalMac = {0x00, 0xFF, 0xDE, 0xAD, 0xBE, 0xAF};
constexpr uint32_t kDefaultPriority = 2307;
constexpr uint32_t kDefaultKatranPos = 8;
constexpr uint32_t kMonitorLimit = 1024;
constexpr bool kNoHc = false;
constexpr uint32_t k1Mbyte = 1024 * 1024;
const std::vector<std::string> kReals = {
    "10.0.0.1",
    "10.0.0.2",
    "10.0.0.3",
    "fc00::1",
    "fc00::2",
    "fc00::3",
};

// packet and bytes stats for reals
const std::vector<::katran::lb_stats> kRealStats = {
    {3, 152},
    {7, 346},
    {5, 291},
    {2, 92},
    {1, 38},
    {3, 156},
};

constexpr uint16_t kVipPort = 80;
constexpr uint8_t kUdp = 17;
constexpr uint8_t kTcp = 6;
constexpr uint32_t kDefaultWeight = 1;
constexpr uint32_t kDportHash = 8;
constexpr uint32_t kQuicVip = 4;
constexpr uint32_t kSrcRouting = 16;
} // namespace

void addReals(
    katran::KatranLb& lb,
    const katran::VipKey& vip,
    const std::vector<std::string>& reals) {
  //
  katran::NewReal real;
  real.weight = kDefaultWeight;
  for (auto& r : reals) {
    real.address = r;
    lb.addRealForVip(real, vip);
  }
}

void addQuicMappings(katran::KatranLb& lb) {
  katran::QuicReal qreal;
  std::vector<katran::QuicReal> qreals;
  auto action = katran::ModifyAction::ADD;
  std::vector<uint32_t> ids = {1022, 1023, 1025, 1024, 1026, 1027};
  for (int i = 0; i < kReals.size(); i++) {
    qreal.address = kReals[i];
    qreal.id = ids[i];
    qreals.push_back(qreal);
  }
  lb.modifyQuicRealsMapping(action, qreals);
}

void testSimulator(katran::KatranLb& lb) {
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
  }
}

void testKatranMonitor(katran::KatranLb& lb) {
  lb.stopKatranMonitor();
  std::this_thread::sleep_for(std::chrono::seconds(1));
  // 0 - tcp non_syn lru miss
  auto buf = lb.getKatranMonitorEventBuffer(0);
  if (buf != nullptr) {
    LOG(INFO) << "buffer length is: " << buf->length();
    auto pcap_file =
        folly::File(FLAGS_monitor_output.c_str(), O_RDWR | O_CREAT | O_TRUNC);
    auto res = folly::writeFull(pcap_file.fd(), buf->data(), buf->length());
    if (res < 0) {
      LOG(ERROR) << "error while trying to write katran monitor output";
    }
  }
}

void prepareLbData(katran::KatranLb& lb) {
  lb.restartKatranMonitor(kMonitorLimit);
  katran::VipKey vip;
  // adding udp vip for tests
  vip.address = "10.200.1.1";
  vip.port = kVipPort;
  vip.proto = kUdp;
  lb.addVip(vip);
  // adding few reals to test
  std::vector<std::string> reals = {"10.0.0.1", "10.0.0.2", "10.0.0.3"};
  std::vector<std::string> reals6 = {"fc00::1", "fc00::2", "fc00::3"};
  addReals(lb, vip, reals);
  // adding tcp vip for tests
  vip.proto = kTcp;
  lb.addVip(vip);
  // adding few reals to test
  addReals(lb, vip, reals);
  // vip which ignores dst_port (testing for TURN-like services)
  vip.address = "10.200.1.2";
  vip.port = 0;
  lb.addVip(vip);
  // adding few reals to test
  addReals(lb, vip, reals);
  // vip which is using only dst port to pick up real
  vip.address = "10.200.1.4";
  lb.addVip(vip);
  // adding few reals to test
  addReals(lb, vip, reals);
  lb.modifyVip(vip, kDportHash);
  // v4inv6 vip. tcp
  vip.address = "10.200.1.3";
  vip.port = kVipPort;
  lb.addVip(vip);
  // adding few reals to test
  addReals(lb, vip, reals6);
  // v6inv6 vip. tcp
  vip.address = "fc00:1::1";
  lb.addVip(vip);
  // adding few reals to test
  addReals(lb, vip, reals6);
  // adding mappings for quic.
  addQuicMappings(lb);
  // adding quic v4 vip.
  vip.proto = kUdp;
  vip.port = 443;
  vip.address = "10.200.1.5";
  lb.addVip(vip);
  lb.modifyVip(vip, kQuicVip);
  addReals(lb, vip, reals);
  // adding quic v6 vip.
  vip.address = "fc00:1::2";
  lb.addVip(vip);
  lb.modifyVip(vip, kQuicVip);
  addReals(lb, vip, reals6);

  // adding healthchecking dst
  lb.addHealthcheckerDst(1, "10.0.0.1");
  lb.addHealthcheckerDst(2, "10.0.0.2");
  lb.addHealthcheckerDst(3, "fc00::1");
}

void prepareOptionalLbData(katran::KatranLb& lb) {
  katran::VipKey vip;
  vip.address = "10.200.1.1";
  vip.port = kVipPort;
  vip.proto = kUdp;
  lb.modifyVip(vip, kSrcRouting);
  vip.address = "fc00:1::1";
  vip.proto = kTcp;
  lb.modifyVip(vip, kSrcRouting);
  lb.addSrcRoutingRule({"192.168.0.0/17"}, "fc00::2307:1");
  lb.addSrcRoutingRule({"192.168.100.0/24"}, "fc00::2307:2");
  lb.addSrcRoutingRule({"fc00:2307::/32"}, "fc00::2307:3");
  lb.addSrcRoutingRule({"fc00:2307::/64"}, "fc00::2307:4");
  lb.addSrcRoutingRule({"fc00:2::/64"}, "fc00::2307:10");
  lb.addInlineDecapDst("fc00:1404::1");
}

void preparePerfTestingLbData(katran::KatranLb& lb) {
  for (auto& dst : kReals) {
    lb.addInlineDecapDst(dst);
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

void testOptionalLbCounters(katran::KatranLb& lb) {
  LOG(INFO) << "Testing optional counter's sanity";
  auto stats = lb.getIcmpTooBigStats();
  if (stats.v1 != 1 || stats.v2 != 1) {
    VLOG(2) << "icmpV4 hits: " << stats.v1 << " icmpv6 hits:" << stats.v2;
    LOG(INFO) << "icmp packet too big counter is incorrect";
  }
  stats = lb.getSrcRoutingStats();
  if (stats.v1 != 2 || stats.v2 != 6) {
    VLOG(2) << "lpm src. local pckts: " << stats.v1 << " remote:" << stats.v2;
    LOG(INFO) << "source based routing counter is incorrect";
  }
  stats = lb.getInlineDecapStats();
  if (stats.v1 != 4) {
    VLOG(2) << "inline decapsulated pckts: " << stats.v1;
    LOG(INFO) << "inline decapsulated packet's counter is incorrect";
  }
  LOG(INFO) << "KatranMonitor stats (only for -DKATRAN_INTROSPECTION)";
  auto monitor_stats = lb.getKatranMonitorStats();
  LOG(INFO) << "limit: " << monitor_stats.limit
            << " amount: " << monitor_stats.amount;
  LOG(INFO) << "Testing of optional counters is complite";
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

void testLbCounters(katran::KatranLb& lb) {
  katran::VipKey vip;
  vip.address = "10.200.1.1";
  vip.port = kVipPort;
  vip.proto = kTcp;
  LOG(INFO) << "Testing counter's sanity. Printing on errors only";
  auto stats = lb.getStatsForVip(vip);
  if ((stats.v1 != 4) || (stats.v2 != 248)) {
    VLOG(2) << "pckts: " << stats.v1 << " bytes: " << stats.v2;
    LOG(INFO) << "per Vip counter is incorrect for vip:" << vip.address;
  }
  stats = lb.getLruStats();
  if ((stats.v1 != 21) || (stats.v2 != 11)) {
    VLOG(2) << "Total pckts: " << stats.v1 << " LRU misses: " << stats.v2;
    LOG(INFO) << "LRU counter is incorrect";
  }
  stats = lb.getLruMissStats();
  if ((stats.v1 != 2) || (stats.v2 != 6)) {
    VLOG(2) << "TCP syns: " << stats.v1 << " TCP non-syns: " << stats.v2;
    LOG(INFO) << "per pckt type LRU miss counter is incorrect";
  }
  stats = lb.getLruFallbackStats();
  if (stats.v1 != 17) {
    VLOG(2) << "FallbackLRU hits: " << stats.v1;
    LOG(INFO) << "LRU fallback counter is incorrect";
  }
  for (int i = 0; i < kReals.size(); i++) {
    auto real = kReals[i];
    auto id = lb.getIndexForReal(real);
    if (id < 0) {
      LOG(INFO) << "Real does not exists: " << real;
      continue;
    }
    stats = lb.getRealStats(id);
    auto expected_stats = kRealStats[i];
    if (stats.v1 != expected_stats.v1 || stats.v2 != expected_stats.v2) {
      VLOG(2) << "stats for real: " << real << " v1: " << stats.v1
              << " v2: " << stats.v2;
      LOG(INFO) << "incorrect stats for real: " << real;
      LOG(INFO) << "Expected to be incorrect w/ non default build flags";
    }
  }
  auto lb_stats = lb.getKatranLbStats();
  if (lb_stats.bpfFailedCalls != 0) {
    VLOG(2) << "failed bpf calls: " << lb_stats.bpfFailedCalls;
    LOG(INFO) << "incorrect stats about katran library internals: "
              << "number of failed bpf syscalls is non zero";
  }
  if (lb_stats.addrValidationFailed != 0) {
    VLOG(2) << "failed ip address validations: "
            << lb_stats.addrValidationFailed;
    LOG(INFO) << "incorrect stats about katran library internals: "
              << "number of failed ip address validations is non zero";
  }

  LOG(INFO) << "Testing of counters is complete";
  return;
}

int main(int argc, char** argv) {
  gflags::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  FLAGS_logtostderr = 1;
  katran::TesterConfig config;
  config.inputFileName = FLAGS_pcap_input;
  config.outputFileName = FLAGS_pcap_output;
  if (FLAGS_gue) {
    config.inputData = katran::testing::inputGueTestFixtures;
    config.outputData = katran::testing::outputGueTestFixtures;
  } else {
    config.inputData = katran::testing::inputTestFixtures;
    config.outputData = katran::testing::outputTestFixtures;
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

  katran::KatranLb lb(kconfig);
  lb.loadBpfProgs();
  auto balancer_prog_fd = lb.getKatranProgFd();
  if (FLAGS_optional_counter_tests) {
    preTestOptionalLbCounters(lb);
  }
  prepareLbData(lb);
  tester.setBpfProgFd(balancer_prog_fd);
  if (!FLAGS_pcap_input.empty()) {
    tester.testPcktsFromPcap();
    return 0;
  } else if (FLAGS_test_from_fixtures) {
    tester.testFromFixture();
    testLbCounters(lb);
    if (FLAGS_optional_counter_tests) {
      postTestOptionalLbCounters(lb);
    }
    testSimulator(lb);
    if (FLAGS_iobuf_storage) {
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
      testOptionalLbCounters(lb);
    }
    return 0;
  } else if (FLAGS_perf_testing) {
    // for perf tests to work katran must be compiled w -DINLINE_DECAP
    preparePerfTestingLbData(lb);
    tester.testPerfFromFixture(FLAGS_repeat, FLAGS_position);
  }
  return 0;
}
