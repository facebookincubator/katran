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

#include <iostream>
#include <string>
#include <vector>

#include <folly/Range.h>
#include <gflags/gflags.h>

#include "KatranOptionalTestFixtures.h"
#include "KatranTestFixtures.h"
#include "XdpTester.h"
#include "katran/lib/KatranLb.h"
#include "katran/lib/KatranLbStructs.h"

DEFINE_string(pcap_input, "", "path to input pcap file");
DEFINE_string(pcap_output, "", "path to output pcap file");
DEFINE_string(balancer_prog, "./balancer_kern.o", "path to balancer bpf prog");
DEFINE_string(healtchecking_prog, "", "path to healthchecking bpf prog");
DEFINE_bool(print_base64, false, "print packets in base64 from pcap file");
DEFINE_bool(test_from_fixtures, false, "run tests on predefined dataset");
DEFINE_bool(perf_testing, false, "run perf tests on predefined dataset");
DEFINE_bool(optional_tests, false, "run optional (kernel specific) tests");
DEFINE_int32(repeat, 1000000, "perf test runs for single packet");
DEFINE_int32(position, -1, "perf test runs for single packet");

namespace {
const std::string kMainInterface = "lo";
const std::string kV4TunInterface = "ipip0";
const std::string kV6TunInterface = "ipip60";
const std::string kNoExternalMap = "";
const std::vector<uint8_t> kDefaultMac = {0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xAF};
constexpr uint32_t kDefaultPriority = 2307;
constexpr uint32_t kDefaultKatranPos = 8;
constexpr bool kNoHc = false;
const std::vector<std::string> kReals = {
    "10.0.0.1",
    "10.0.0.2",
    "10.0.0.3",
    "fc00::1",
    "fc00::2",
    "fc00::3",
};

const std::vector<::katran::lb_stats> kRealStats = {
    {3, 150},
    {7, 344},
    {4, 236},
    {2, 91},
    {1, 38},
    {2, 121},
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

void prepareLbData(katran::KatranLb& lb) {
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

void testOptionalLbCounters(katran::KatranLb& lb) {
  LOG(INFO) << "Testing optional counter's sanity";
  auto stats = lb.getIcmpTooBigStats();
  if (stats.v1 != 1 || stats.v2 != 1) {
    VLOG(2) << "icmpV4 hits: " << stats.v1 << " icmpv6 hits:" << stats.v2;
    LOG(INFO) << "icmp packet too big counter is incorrect";
  }
  stats = lb.getSrcRoutingStats();
  if (stats.v1 != 2 || stats.v2 != 4) {
    VLOG(2) << "lpm src. local pckts: " << stats.v1 << " remote:" << stats.v2;
    LOG(INFO) << "source based routing counter is incorrect";
  }
  stats = lb.getInlineDecapStats();
  if (stats.v1 != 2) {
    VLOG(2) << "inline decapsulated pckts: " << stats.v1;
    LOG(INFO) << "inline decapsulated packet's counter is incorrect";
  }
  LOG(INFO) << "Testing of optional counters is complite";
}

void testLbCounters(katran::KatranLb& lb) {
  katran::VipKey vip;
  vip.address = "10.200.1.1";
  vip.port = kVipPort;
  vip.proto = kTcp;
  LOG(INFO) << "Testing counter's sanity. Printing on errors only";
  auto stats = lb.getStatsForVip(vip);
  if ((stats.v1 != 3) || (stats.v2 != 193)) {
    VLOG(2) << "pckts: " << stats.v1 << " bytes: " << stats.v2;
    LOG(INFO) << "per Vip counter is incorrect";
  }
  stats = lb.getLruStats();
  if ((stats.v1 != 19) || (stats.v2 != 11)) {
    VLOG(2) << "Total pckts: " << stats.v1 << " LRU misses: " << stats.v2;
    LOG(INFO) << "LRU counter is incorrect";
  }
  stats = lb.getLruMissStats();
  if ((stats.v1 != 2) || (stats.v2 != 6)) {
    VLOG(2) << "TCP syns: " << stats.v1 << " TCP non-syns: " << stats.v2;
    LOG(INFO) << "per pckt type LRU miss counter is incorrect";
  }
  stats = lb.getLruFallbackStats();
  if (stats.v1 != 15) {
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
  config.inputData = katran::testing::inputTestFixtures;
  config.outputData = katran::testing::outputTestFixtures;
  katran::XdpTester tester(config);
  if (FLAGS_print_base64) {
    if (FLAGS_pcap_input.empty()) {
      std::cout << "pcap_input is not specified! exiting";
      return 1;
    }
    tester.printPcktBase64();
    return 0;
  }
  katran::KatranLb lb(katran::KatranConfig{kMainInterface,
                                           kV4TunInterface,
                                           kV6TunInterface,
                                           FLAGS_balancer_prog,
                                           FLAGS_healtchecking_prog,
                                           kDefaultMac,
                                           kDefaultPriority,
                                           kNoExternalMap,
                                           kDefaultKatranPos,
                                           kNoHc});
  lb.loadBpfProgs();
  auto balancer_prog_fd = lb.getKatranProgFd();
  prepareLbData(lb);
  tester.setBpfProgFd(balancer_prog_fd);
  if (!FLAGS_pcap_input.empty()) {
    tester.testPcktsFromPcap();
    return 0;
  } else if (FLAGS_test_from_fixtures) {
    tester.testFromFixture();
    testLbCounters(lb);
    if (FLAGS_optional_tests) {
      prepareOptionalLbData(lb);
      LOG(INFO) << "Running optional tests. they could fail if requirements "
                << "are not satisfied";
      tester.resetTestFixtures(
          katran::testing::inputOptionalTestFixtures,
          katran::testing::outputOptionalTestFixtures);
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
