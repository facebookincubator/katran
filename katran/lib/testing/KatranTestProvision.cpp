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

#include "katran/lib/testing/KatranTestProvision.h"

namespace katran {
namespace testing {
const std::string kMainInterface = "lo";
const std::string kV4TunInterface = "lo";
const std::string kV6TunInterface = "lo";
const std::string kNoExternalMap = "";
const std::vector<uint8_t> kDefaultMac = {0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xAF};
const std::vector<uint8_t> kLocalMac = {0x00, 0xFF, 0xDE, 0xAD, 0xBE, 0xAF};

const std::vector<std::string> kReals = {
    "10.0.0.1",
    "10.0.0.2",
    "10.0.0.3",
    "fc00::1",
    "fc00::2",
    "fc00::3",
};

// packet and bytes stats for reals corresponding to each index in the kReals
const std::vector<::katran::lb_stats> kDefaultRealStats = {
    {4, 190},
    {7, 346},
    {5, 291},
    {2, 92},
    {2, 76},
    {3, 156},
};

const std::vector<::katran::lb_stats> kTPRRealStats = {
    {0, 0},
    {3, 181},
    {4, 244},
    {9, 423},
    {0, 0},
    {0, 0},
};

const std::map<TestMode, std::vector<::katran::lb_stats>> kRealStats = {
    {TestMode::DEFAULT, kDefaultRealStats},
    {TestMode::GUE, kDefaultRealStats},
    {TestMode::TPR, kTPRRealStats}};

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
  std::vector<uint16_t> ids = {1022, 1023, 1025, 1024, 1026, 1027};
  for (int i = 0; i < kReals.size(); i++) {
    // CIDv1
    qreal.address = kReals[i];
    qreal.id = ids[i];
    qreals.push_back(qreal);
    // // CIDv2
    qreal.address = kReals[i];
    constexpr uint32_t twJobMask = 0x030000; // tw job set to 3
    qreal.id = twJobMask | ids[i];
    qreals.push_back(qreal);
  }
  lb.modifyQuicRealsMapping(action, qreals);
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

  // add vip to test local flag
  vip.address = "10.200.1.6";
  vip.port = kVipPort;
  vip.proto = kUdp;
  lb.addVip(vip);
  // add local flag to vip
  lb.modifyVip(vip, kLocalVip);
  // add few reals to test
  addReals(lb, vip, {"10.0.0.6"});
  // add local flag to reals
  lb.modifyReal("10.0.0.6", kLocalReal);
}

void preparePerfTestingLbData(katran::KatranLb& lb) {
  for (auto& dst : kReals) {
    lb.addInlineDecapDst(dst);
  }
}

const std::vector<::katran::lb_stats> KatranTestParam::expectedRealStats() noexcept {
  auto it = kRealStats.find(mode);
  CHECK(it != kRealStats.end());
  return it->second;
}

uint64_t KatranTestParam::expectedTotalPktsForVip(const katran::VipKey& vip) noexcept {
  if (perVipCounters.count(vip) == 0) {
    return 0;
  }
  return perVipCounters[vip].first;
}
uint64_t KatranTestParam::expectedTotalBytesForVip(const katran::VipKey& vip) noexcept {
  if (perVipCounters.count(vip) == 0) {
    return 0;
  }
  return perVipCounters[vip].second;
}
uint64_t KatranTestParam::expectedTotalPkts() noexcept {
  return _lookup_counter(KatranTestCounters::TOTAL_PKTS);
}
uint64_t KatranTestParam::expectedTotalLruMisses() noexcept {
  return _lookup_counter(KatranTestCounters::LRU_MISSES);
}
uint64_t KatranTestParam::expectedTotalTcpSyns() noexcept {
  return _lookup_counter(KatranTestCounters::TCP_SYNS);
}
uint64_t KatranTestParam::expectedTotalTcpNonSynLruMisses() noexcept {
  return _lookup_counter(KatranTestCounters::NON_SYN_LRU_MISSES);
}
uint64_t KatranTestParam::expectedTotalLruFallbackHits() noexcept {
  return _lookup_counter(KatranTestCounters::LRU_FALLBACK_HITS);
}
uint64_t KatranTestParam::expectedQuicRoutingWithCh() noexcept {
  return _lookup_counter(KatranTestCounters::QUIC_ROUTING_WITH_CH);
}
uint64_t KatranTestParam::expectedQuicRoutingWithCid() noexcept {
  return _lookup_counter(KatranTestCounters::QUIC_ROUTING_WITH_CID);
}
uint64_t KatranTestParam::expectedQuicCidV1Counts() noexcept {
  return _lookup_counter(KatranTestCounters::QUIC_CID_V1);
}
uint64_t KatranTestParam::expectedQuicCidV2Counts() noexcept {
  return _lookup_counter(KatranTestCounters::QUIC_CID_V2);
}
uint64_t KatranTestParam::expectedQuicCidDropsReal0Counts() noexcept {
  return _lookup_counter(KatranTestCounters::QUIC_CID_DROPS_REAL_0);
}
uint64_t KatranTestParam::expectedQuicCidDropsNoRealCounts() noexcept {
  return _lookup_counter(KatranTestCounters::QUIC_CID_DROPS_NO_REAL);
}
uint64_t KatranTestParam::expectedTcpServerIdRoutingCounts() noexcept {
  return _lookup_counter(KatranTestCounters::TCP_SERVER_ID_ROUNTING);
}
uint64_t KatranTestParam::expectedTcpServerIdRoutingFallbackCounts() noexcept {
  return _lookup_counter(KatranTestCounters::TCP_SERVER_ID_ROUTING_FALLBACK_CH);
}
uint64_t KatranTestParam::expectedTotalFailedBpfCalls() noexcept {
  return _lookup_counter(KatranTestCounters::TOTAL_FAILED_BPF_CALLS);
}
uint64_t KatranTestParam::expectedTotalAddressValidations() noexcept {
  return _lookup_counter(KatranTestCounters::TOTAL_ADDRESS_VALIDATION_FAILED);
}
uint64_t KatranTestParam::expectedIcmpV4Counts() noexcept {
  return _lookup_counter(KatranTestCounters::ICMP_V4_COUNTS);
}
uint64_t KatranTestParam::expectedIcmpV6Counts() noexcept {
  return _lookup_counter(KatranTestCounters::ICMP_V6_COUNTS);
}
uint64_t KatranTestParam::expectedSrcRoutingPktsLocal() noexcept {
  return _lookup_counter(KatranTestCounters::SRC_ROUTING_PKTS_LOCAL);
}
uint64_t KatranTestParam::expectedSrcRoutingPktsRemote() noexcept {
  return _lookup_counter(KatranTestCounters::SRC_ROUTING_PKTS_REMOTE);
}
uint64_t KatranTestParam::expectedInlineDecapPkts() noexcept {
  return _lookup_counter(KatranTestCounters::INLINE_DECAP_PKTS);
}
uint64_t KatranTestParam::_lookup_counter(KatranTestCounters counter) noexcept {
  if (expectedCounters.count(counter) == 0) {
    return 0;
  }
  return expectedCounters[counter];
}

} // namespace testing
} // namespace katran
