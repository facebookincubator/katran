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
const std::vector<::katran::lb_stats> kRealStats = {
    {4, 190},
    {7, 346},
    {5, 291},
    {2, 92},
    {2, 76},
    {3, 156},
};

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
  // v6inv4 vip. tcp
  vip.address = "fc00:1::3";
  vip.port = kVipPort;
  lb.addVip(vip);
  // adding few reals to test
  addReals(lb, vip, reals);
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

} // namespace testing
} // namespace katran
