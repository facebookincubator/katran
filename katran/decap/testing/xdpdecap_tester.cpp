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

#include <gflags/gflags.h>

#include "katran/decap/XdpDecap.h"
#include "katran/decap/XdpDecapStructs.h"
#include "katran/decap/testing/XdpDecapGueTestFixtures.h"
#include "katran/decap/testing/XdpDecapTestFixtures.h"
#include "katran/lib/testing/framework/BpfTester.h"

DEFINE_string(pcap_input, "", "path to input pcap file");
DEFINE_string(pcap_output, "", "path to output pcap file");
DEFINE_string(decap_prog, "./decap_kern.o", "path to balancer bpf prog");
DEFINE_bool(print_base64, false, "print packets in base64 from pcap file");
DEFINE_bool(test_from_fixtures, false, "run tests on predefined dataset");
DEFINE_bool(gue, false, "run GUE tests instead of IPIP ones");
DEFINE_bool(perf_testing, false, "run perf tests on predefined dataset");
DEFINE_int32(repeat, 1000000, "perf test runs for single packet");
DEFINE_int32(position, -1, "perf test runs for single packet");

void testXdpDecapCounters(katran::XdpDecap& decap) {
  LOG(INFO) << "Testing counter's sanity";
  auto stats = decap.getXdpDecapStats();
  int expectedV4DecapPkts = 1;
  int expectedV6DecapPkts = FLAGS_gue ? 9 : 2;
  int expectedTotalPkts = FLAGS_gue ? 10 : 7;
  int expectedTotalTPRPkts = 4;
  int expectedMisroutedTPRPkts = 3;
  if (stats.decap_v4 != expectedV4DecapPkts ||
      stats.decap_v6 != expectedV6DecapPkts ||
      stats.total != expectedTotalPkts ||
      stats.tpr_total != expectedTotalTPRPkts ||
      stats.tpr_misrouted != expectedMisroutedTPRPkts) {
    LOG(ERROR) << "decap_v4 pkts: " << stats.decap_v4
               << ", expected decap_v4 pkts: " << expectedV4DecapPkts
               << ", decap_v6: " << stats.decap_v6
               << ", expected decap_v6 pkts: " << expectedV6DecapPkts
               << " total: " << stats.total
               << ", expected total_pkts: " << expectedTotalPkts
               << " tpr total: " << stats.tpr_total
               << ", expected tpr total pkts: " << expectedTotalTPRPkts
               << " tpr misrouted: " << stats.tpr_misrouted
               << ", expected tpr misrouted: " << expectedMisroutedTPRPkts;
    LOG(ERROR) << "[FAIL] Incorrect decap counters";
    return;
  }
  LOG(INFO) << "[SUCCESS] Testing of counters is complete";
}

int main(int argc, char** argv) {
  gflags::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  FLAGS_logtostderr = 1;
  katran::TesterConfig config;
  config.inputFileName = FLAGS_pcap_input;
  config.outputFileName = FLAGS_pcap_output;
  config.testData = FLAGS_gue ? katran::testing::gueTestFixtures
                              : katran::testing::testFixtures;
  katran::BpfTester tester(config);
  if (FLAGS_print_base64) {
    if (FLAGS_pcap_input.empty()) {
      std::cout << "pcap_input is not specified! exiting";
      return 1;
    }
    tester.printPcktBase64();
    return 0;
  }
  katran::XdpDecap decap(katran::XdpDecapConfig{FLAGS_decap_prog});
  decap.loadXdpDecap();
  auto decap_prog_fd = decap.getXdpDecapFd();
  tester.setBpfProgFd(decap_prog_fd);
  decap.setSeverId(100);

  if (!FLAGS_pcap_input.empty()) {
    tester.testPcktsFromPcap();
    return 0;
  } else if (FLAGS_test_from_fixtures) {
    tester.testFromFixture();
    testXdpDecapCounters(decap);
    return 0;
  } else if (FLAGS_perf_testing) {
    tester.testPerfFromFixture(FLAGS_repeat, FLAGS_position);
  }
  return 0;
}
