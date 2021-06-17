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
#include "katran/lib/testing/KatranTPRTestFixtures.h"
#include "katran/lib/testing/KatranTestFixtures.h"

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
      .inputData = testMode == TestMode::GUE
          ? katran::testing::inputGueTestFixtures
          : katran::testing::inputTestFixtures,
      .outputData = testMode == TestMode::GUE
          ? katran::testing::outputGueTestFixtures
          : katran::testing::outputTestFixtures,
      .expectedCounters =
          {
              {KatranTestCounters::TOTAL_PKTS, 23},
              {KatranTestCounters::LRU_MISSES, 11},
              {KatranTestCounters::TCP_SYNS, 2},
              {KatranTestCounters::NON_SYN_LRU_MISSES, 6},
              {KatranTestCounters::LRU_FALLBACK_HITS, 17},
              {KatranTestCounters::QUIC_ROUTING_WITH_CH, 5},
              {KatranTestCounters::QUIC_ROUTING_WITH_CID, 6},
              {KatranTestCounters::QUIC_CID_V1, 4},
              {KatranTestCounters::QUIC_CID_V2, 2},
              {KatranTestCounters::QUIC_CID_DROPS_REAL_0, 0},
              {KatranTestCounters::QUIC_CID_DROPS_NO_REAL, 4},
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
      .inputData = katran::testing::inputTPRTestFixtures,
      .outputData = katran::testing::outputTPRTestFixtures,
      .expectedCounters =
          {
              {KatranTestCounters::TOTAL_PKTS, 16},
              {KatranTestCounters::LRU_MISSES, 4},
              {KatranTestCounters::TCP_SYNS, 1},
              {KatranTestCounters::NON_SYN_LRU_MISSES, 3},
              {KatranTestCounters::LRU_FALLBACK_HITS, 16},
              {KatranTestCounters::TCP_SERVER_ID_ROUNTING, 7},
              {KatranTestCounters::TCP_SERVER_ID_ROUTING_FALLBACK_CH, 8},
              {KatranTestCounters::TOTAL_FAILED_BPF_CALLS, 0},
              {KatranTestCounters::TOTAL_ADDRESS_VALIDATION_FAILED, 0},
          },
      .perVipCounters = {{vip, std::pair<uint64_t, uint64_t>(4, 244)}}};
  return testParam;
}

} // namespace testing
} // namespace katran
