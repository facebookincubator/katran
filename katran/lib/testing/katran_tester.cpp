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

#include "KatranTestFixtures.h"
#include "KatranOptionalTestFixtures.h"
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

constexpr uint16_t kVipPort = 80;
constexpr uint8_t kUdp = 17;
constexpr uint8_t kTcp = 6;
constexpr uint32_t kDefaultWeight = 1;
constexpr uint32_t kDportHash = 8;
constexpr uint32_t kQuicVip = 4;
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
  std::vector<std::string> reals = {
      "10.0.0.1",
      "10.0.0.2",
      "10.0.0.3",
      "fc00::1",
      "fc00::2",
      "fc00::3",
  };
  std::vector<uint32_t> ids = {1022, 1023, 1025, 1024, 1026, 1027};
  for (int i = 0; i < reals.size(); i++) {
    qreal.address = reals[i];
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

void prepareOptionalLbData(katran::KatranLb& /* unused */) {
}

void testOptionalLbCounters(katran::KatranLb& lb) {
  LOG(INFO) << "Testing optional counter's sanity";
  auto stats = lb.getIcmpTooBigStats();
  if (stats.v1 != 1 || stats.v2 != 1) {
    VLOG(2) << "icmpV4 hits: " << stats.v1 << " icmpv6 hits:" << stats.v2;
    LOG(INFO) << "icmp packet too big counter is incorrect";
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
  if ((stats.v1 != 17) || (stats.v2 != 10)) {
    VLOG(2) << "Total pckts: " << stats.v1 << " LRU misses: " << stats.v2;
    LOG(INFO) << "LRU counter is incorrect";
  }
  stats = lb.getLruMissStats();
  if ((stats.v1 != 2) || (stats.v2 != 6)) {
    VLOG(2) << "TCP syns: " << stats.v1 << " TCP non-syns: " << stats.v2;
    LOG(INFO) << "per pckt type LRU miss counter is incorrect";
  }
  stats = lb.getLruFallbackStats();
  if (stats.v1 != 13) {
    VLOG(2) << "FallbackLRU hits: " << stats.v1;
    LOG(INFO) << "LRU fallback counter is incorrect";
  }
  LOG(INFO) << "Testing of counters is complite";
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
    tester.testPerfFromFixture(FLAGS_repeat, FLAGS_position);
  }
  return 0;
}
