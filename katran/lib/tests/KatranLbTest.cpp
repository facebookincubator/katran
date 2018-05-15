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

#include <folly/Format.h>
#include <gtest/gtest.h>

#include "katran/lib/KatranLb.h"

namespace katran {

class KatranLbTest : public ::testing::Test {
 protected:
  KatranLbTest()
      : lb(KatranConfig{"eth0",
                        "ipip0",
                        "ipip60",
                        "./lb.o",
                        "./hc.0",
                        {0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E},
                        1,
                        "",
                        1,
                        true,
                        512,
                        4096,
                        65537,
                        true}){};

  void SetUp() override {
    v1.address = "fc01::1";
    v1.port = 443;
    v1.proto = 6;
    v2.address = "fc01::2";
    v1.port = 443;
    v2.proto = 6;
    r1.address = "192.168.1.1";
    r1.weight = 10;
    r2.address = "fc00::1";
    r2.weight = 12;
    // adding ~4k reals.
    NewReal real1, real2;
    QuicReal qreal1, qreal2;
    real1.weight = 1;
    real2.weight = 1;
    int k;
    for (int i = 0; i < 16; i++) {
      for (int j = 0; j < 256; j++) {
        k = (i * 256 + j);
        if (k <= 4096) {
          real1.address = folly::sformat("10.0.{}.{}", i, j);
          newReals1.push_back(real1);
          qreal1.address = real1.address;
          qreal1.id = k;
          qReals1.push_back(qreal1);
          real2.address = folly::sformat("10.1.{}.{}", i, j);
          newReals2.push_back(real2);
          qreal2.address = real2.address;
          qreal2.id = k;
          qReals2.push_back(qreal2);
        }
      }
    }
  };

  KatranLb lb;
  VipKey v1;
  VipKey v2;
  NewReal r1;
  NewReal r2;
  std::vector<NewReal> newReals1;
  std::vector<NewReal> newReals2;
  std::vector<QuicReal> qReals1;
  std::vector<QuicReal> qReals2;
};

TEST_F(KatranLbTest, testChangeMac) {
  std::vector<uint8_t> mac = {0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0F};
  ASSERT_EQ(lb.changeMac(mac), true);
  auto default_mac = lb.getMac();
  ASSERT_EQ(default_mac.size(), 6);
  for (int i = 0; i < 6; i++) {
    default_mac[i] = mac[i];
  }
};

TEST_F(KatranLbTest, testVipHelpers) {
  VipKey v;
  v.address = "fc00::3";
  v.port = 0;
  v.proto = 6;
  // trying to delete non-existing vip.
  ASSERT_EQ(lb.delVip(v1), false);
  // addding and removing vip;
  ASSERT_EQ(lb.addVip(v2), true);
  ASSERT_EQ(lb.delVip(v2), true);
  for (int i = 0; i < 512; i++) {
    v.port = i;
    ASSERT_EQ(lb.addVip(v), true);
  }
  // trying to add more than 512 vips
  v.port = 1000;
  ASSERT_EQ(lb.addVip(v), false);
};

TEST_F(KatranLbTest, testRealHelpers) {
  lb.addVip(v1);

  // deleting non-existing real; true because it's nop and not an error
  ASSERT_EQ(lb.delRealForVip(r1, v1), true);
  // adding new real to non-existing vip
  ASSERT_EQ(lb.addRealForVip(r1, v2), false);
  // adding real to existing vip
  ASSERT_EQ(lb.addRealForVip(r1, v1), true);
};

TEST_F(KatranLbTest, testVipStatsHelper) {
  lb.addVip(v1);
  auto stats = lb.getStatsForVip(v1);
  ASSERT_EQ(stats.v1, 0);
  ASSERT_EQ(stats.v2, 0);
};

TEST_F(KatranLbTest, testLruStatsHelper) {
  auto stats = lb.getLruStats();
  ASSERT_EQ(stats.v1, 0);
  ASSERT_EQ(stats.v2, 0);
};

TEST_F(KatranLbTest, testLruMissStatsHelper) {
  auto stats = lb.getLruMissStats();
  ASSERT_EQ(stats.v1, 0);
  ASSERT_EQ(stats.v2, 0);
};

TEST_F(KatranLbTest, testHcHelpers) {
  // deleting non-existing healthcheck
  ASSERT_EQ(lb.delHealthcheckerDst(1000), false);
  ASSERT_EQ(lb.addHealthcheckerDst(1000, "192.168.1.1"), true);
  ASSERT_EQ(lb.delHealthcheckerDst(1000), true);
};

TEST_F(KatranLbTest, getVipFlags) {
  lb.addVip(v1, 2307);
  ASSERT_EQ(lb.getVipFlags(v1), 2307);
};

TEST_F(KatranLbTest, getAllVips) {
  lb.addVip(v1);
  lb.addVip(v2);
  ASSERT_EQ(lb.getAllVips().size(), 2);
};

TEST_F(KatranLbTest, testUpdateRealsHelper) {
  lb.addVip(v1);
  lb.addVip(v2);
  ModifyAction action = ModifyAction::ADD;
  // ading max amount (4096) of reals
  ASSERT_EQ(lb.modifyRealsForVip(action, newReals1, v1), true);
  ASSERT_EQ(lb.modifyRealsForVip(action, newReals2, v2), true);
  // v1 has all reals;
  ASSERT_EQ(lb.getRealsForVip(v1).size(), 4096);
  // v2 has 0 reals because when we were trying to add new ones there was no
  // more space for new reals.
  ASSERT_EQ(lb.getRealsForVip(v2).size(), 0);
  // but if we add same reals as for v1 - everything must works
  ASSERT_EQ(lb.modifyRealsForVip(action, newReals1, v2), true);
  ASSERT_EQ(lb.getRealsForVip(v2).size(), 4096);
  action = ModifyAction::DEL;
  // deleting 4k reals
  ASSERT_EQ(lb.modifyRealsForVip(action, newReals1, v1), true);
  ASSERT_EQ(lb.modifyRealsForVip(action, newReals1, v2), true);
  // retrying to add new rels to v2.
  action = ModifyAction::ADD;
  ASSERT_EQ(lb.modifyRealsForVip(action, newReals2, v2), true);
  ASSERT_EQ(lb.getRealsForVip(v2).size(), 4096);
};

TEST_F(KatranLbTest, testUpdateQuicRealsHelper) {
  lb.addVip(v1);
  lb.addVip(v2);
  ModifyAction action = ModifyAction::ADD;
  // ading max amount (4096) of reals
  lb.modifyQuicRealsMapping(action, qReals2);
  ASSERT_EQ(lb.modifyRealsForVip(action, newReals1, v1), true);
  ASSERT_EQ(lb.modifyRealsForVip(action, newReals2, v2), true);
  // v1 has no reals, because quic consumed all of em;
  ASSERT_EQ(lb.getRealsForVip(v1).size(), 0);
  // v2 has same reals addresses as quic, so all of was added as well.
  ASSERT_EQ(lb.getRealsForVip(v2).size(), 4096);
  ASSERT_EQ(lb.getQuicRealsMapping().size(), 4096);
  action = ModifyAction::DEL;
  // deleting 4k reals
  ASSERT_EQ(lb.modifyRealsForVip(action, newReals2, v2), true);
  lb.modifyQuicRealsMapping(action, qReals2);
  ASSERT_EQ(lb.getQuicRealsMapping().size(), 0);
  // retrying to add new rels to v1.
  action = ModifyAction::ADD;
  ASSERT_EQ(lb.modifyRealsForVip(action, newReals1, v1), true);
  ASSERT_EQ(lb.getRealsForVip(v1).size(), 4096);
};

TEST_F(KatranLbTest, testUpdateQuicReal) {
  QuicReal real;
  std::vector<QuicReal> reals;
  ModifyAction action = ModifyAction::ADD;
  real.address = "10.0.0.1";
  real.id = 1;
  reals.push_back(real);
  // adding one mapping
  lb.modifyQuicRealsMapping(action, reals);
  ASSERT_EQ(lb.getQuicRealsMapping().size(), 1);
  // adding mapping with id > max allowed.
  reals[0].id = 4096;
  lb.modifyQuicRealsMapping(action, reals);
  ASSERT_EQ(lb.getQuicRealsMapping().size(), 1);
  // adding mapping with existing id
  reals[0].id = 1;
  lb.modifyQuicRealsMapping(action, reals);
  ASSERT_EQ(lb.getQuicRealsMapping().size(), 1);
  action = ModifyAction::DEL;
  // deleting non existing mapping
  reals[0].address = "10.0.0.2";
  lb.modifyQuicRealsMapping(action, reals);
  ASSERT_EQ(lb.getQuicRealsMapping().size(), 1);
  // deleting existing mapping
  reals[0].address = "10.0.0.1";
  lb.modifyQuicRealsMapping(action, reals);
  ASSERT_EQ(lb.getQuicRealsMapping().size(), 0);
}

TEST_F(KatranLbTest, getRealsForVip) {
  lb.addVip(v1);
  lb.addRealForVip(r1, v1);
  lb.addRealForVip(r2, v1);
  ASSERT_EQ(lb.getRealsForVip(v1).size(), 2);
};

TEST_F(KatranLbTest, getHealthcheckersDst) {
  lb.addHealthcheckerDst(1, "192.168.1.1");
  lb.addHealthcheckerDst(2, "192.168.1.1");
  auto hcs = lb.getHealthcheckersDst();
  ASSERT_EQ(hcs.size(), 2);
};

} // namespace katran
