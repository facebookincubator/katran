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

#include <fmt/core.h>
#include <gtest/gtest.h>

#include "katran/lib/KatranLb.h"

namespace katran {

constexpr int kMaxRealTest = 4096;
// real index 0 is preserved. So the real capacity would be
// sizeof(reals array)-1.
constexpr int kMaxNumOfReals = kMaxRealTest - 1;

class KatranLbTest : public ::testing::Test {
 protected:
  KatranLbTest() {
    KatranConfig katranConfig{
        "eth0", // mainInterface
        "ipip0", // v4TunInterface
        "ipip60", // v6TunInterface
        "./lb->o", // balancerProgPath
        "./hc.0", // healthcheckingProgPath
        {0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E}, // defaultMac
        1, // priority
        "", // rootMapPath
        1, // rootMapPos
        true, // enableHc
        false, // tunnelBasedEncap
        false, // disableForwarding
        512, // maxVips
        kMaxRealTest, // maxReals
        65537, // chRingSize
        true, // testing
        1, // LruSize
        {}, // forwardingCores
        {}, // numaNodes
        10, // maxLpmSrcSize
        4, // maxDecapDst
        "eth0", // hcInterface
        0, // xdpAttachFlags
        {}, // monitorConfig
        false, // memlockUnlimited
        {}, // localMac
    };
    lb = std::make_unique<KatranLb>(
        katranConfig,
        std::make_unique<katran::BpfAdapter>(katranConfig.memlockUnlimited));
  }

  void SetUp() override {
    v1.address = "fc01::1";
    v1.port = 443;
    v1.proto = 6;
    v2.address = "fc01::2";
    v2.port = 443;
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
        if (k < kMaxNumOfReals) {
          real1.address = fmt::format("10.0.{}.{}", i, j);
          newReals1.push_back(real1);
          qreal1.address = real1.address;
          qreal1.id = k;
          qReals1.push_back(qreal1);
          real2.address = fmt::format("10.1.{}.{}", i, j);
          newReals2.push_back(real2);
          qreal2.address = real2.address;
          qreal2.id = k;
          qReals2.push_back(qreal2);
        }
      }
    }
  };

  std::unique_ptr<KatranLb> lb;
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
  ASSERT_EQ(lb->changeMac(mac), true);
  auto default_mac = lb->getMac();
  ASSERT_EQ(default_mac.size(), 6);
  for (int i = 0; i < 6; i++) {
    default_mac[i] = mac[i];
  }
};

TEST_F(KatranLbTest, testIfIndex) {
  auto indices = lb->getIndexOfNetworkInterfaces();
  ASSERT_EQ(indices.size(), 2);
  auto it = indices.find(kMainIntfPos);
  ASSERT_FALSE(it == indices.end());
  it = indices.find(kHcIntfPos);
  ASSERT_FALSE(it == indices.end());
  it = indices.find(kIpv4TunPos);
  ASSERT_TRUE(it == indices.end());
  it = indices.find(kIpv6TunPos);
  ASSERT_TRUE(it == indices.end());
};

TEST_F(KatranLbTest, testVipHelpers) {
  VipKey v;
  v.address = "fc00::3";
  v.port = 0;
  v.proto = 6;
  // trying to delete non-existing vip.
  ASSERT_FALSE(lb->delVip(v1));
  // addding and removing vip;
  ASSERT_TRUE(lb->addVip(v2));
  ASSERT_TRUE(lb->delVip(v2));
  for (int i = 0; i < 512; i++) {
    v.port = i;
    ASSERT_TRUE(lb->addVip(v));
  }
  // trying to add more than 512 vips
  v.port = 1000;
  ASSERT_FALSE(lb->addVip(v));
};

TEST_F(KatranLbTest, testAddingInvalidVip) {
  VipKey v;
  v.address = "fc00::/64";
  v.port = 0;
  v.proto = 6;
  // adding vip which is an network address, not a host.
  ASSERT_FALSE(lb->addVip(v));
};

TEST_F(KatranLbTest, testRealHelpers) {
  lb->addVip(v1);

  // deleting non-existing real; true because it's nop and not an error
  ASSERT_TRUE(lb->delRealForVip(r1, v1));
  // adding new real to non-existing vip
  ASSERT_FALSE(lb->addRealForVip(r1, v2));
  // adding real to existing vip
  ASSERT_TRUE(lb->addRealForVip(r1, v1));
};

TEST_F(KatranLbTest, testRealFlags) {
  lb->addVip(v1);
  lb->addRealForVip(r1, v1);
  // modify existing real (set flags)
  ASSERT_TRUE(lb->modifyReal(r1.address, 0xf0, true));
  // modify non-existing real
  ASSERT_FALSE(lb->modifyReal("1.2.3.4", 0xff, true));
  // set and get flags (ipv4/ipv6 specific flag should not be changed)
  lb->modifyReal(r1.address, 0xff, true);
  auto reals = lb->getRealsForVip(v1);
  ASSERT_EQ(reals[0].flags, 0xfe);
  // check unset flags
  lb->modifyReal(r1.address, 0x10, false);
  reals = lb->getRealsForVip(v1);
  ASSERT_EQ(reals[0].flags, 0xee);
};

TEST_F(KatranLbTest, testVipStatsHelper) {
  lb->addVip(v1);
  auto stats = lb->getStatsForVip(v1);
  ASSERT_EQ(stats.v1, 0);
  ASSERT_EQ(stats.v2, 0);
};

TEST_F(KatranLbTest, testLruStatsHelper) {
  auto stats = lb->getLruStats();
  ASSERT_EQ(stats.v1, 0);
  ASSERT_EQ(stats.v2, 0);
};

TEST_F(KatranLbTest, testLruMissStatsHelper) {
  auto stats = lb->getLruMissStats();
  ASSERT_EQ(stats.v1, 0);
  ASSERT_EQ(stats.v2, 0);
};

TEST_F(KatranLbTest, testHcHelpers) {
  // deleting non-existing healthcheck
  ASSERT_FALSE(lb->delHealthcheckerDst(1000));
  ASSERT_TRUE(lb->addHealthcheckerDst(1000, "192.168.1.1"));
  ASSERT_TRUE(lb->delHealthcheckerDst(1000));
};

TEST_F(KatranLbTest, getVipFlags) {
  lb->addVip(v1, 2307);
  ASSERT_EQ(lb->getVipFlags(v1), 2307);
};

TEST_F(KatranLbTest, getAllVips) {
  lb->addVip(v1);
  lb->addVip(v2);
  ASSERT_EQ(lb->getAllVips().size(), 2);
};

TEST_F(KatranLbTest, testUpdateRealsHelper) {
  lb->addVip(v1);
  lb->addVip(v2);
  ModifyAction action = ModifyAction::ADD;
  // ading max amount (kMaxNumOfReals) of reals
  ASSERT_TRUE(lb->modifyRealsForVip(action, newReals1, v1));
  ASSERT_TRUE(lb->modifyRealsForVip(action, newReals2, v2));
  // v1 has all reals;
  ASSERT_EQ(lb->getRealsForVip(v1).size(), kMaxNumOfReals);
  // v2 has 0 reals because when we were trying to add new ones there was no
  // more space for new reals.
  ASSERT_EQ(lb->getRealsForVip(v2).size(), 0);
  // but if we add same reals as for v1 - everything must works
  ASSERT_TRUE(lb->modifyRealsForVip(action, newReals1, v2));
  ASSERT_EQ(lb->getRealsForVip(v2).size(), kMaxNumOfReals);
  action = ModifyAction::DEL;
  // deleting 4k reals
  ASSERT_TRUE(lb->modifyRealsForVip(action, newReals1, v1));
  ASSERT_TRUE(lb->modifyRealsForVip(action, newReals1, v2));
  // retrying to add new rels to v2.
  action = ModifyAction::ADD;
  ASSERT_TRUE(lb->modifyRealsForVip(action, newReals2, v2));
  ASSERT_EQ(lb->getRealsForVip(v2).size(), kMaxNumOfReals);
  ASSERT_EQ(lb->getNumToRealMap().size(), kMaxNumOfReals);
};

TEST_F(KatranLbTest, testUpdateQuicRealsHelper) {
  lb->addVip(v1);
  lb->addVip(v2);
  ModifyAction action = ModifyAction::ADD;
  // ading max amount (kMaxNumOfReals) of reals
  lb->modifyQuicRealsMapping(action, qReals2);
  ASSERT_TRUE(lb->modifyRealsForVip(action, newReals1, v1));
  ASSERT_TRUE(lb->modifyRealsForVip(action, newReals2, v2));
  // v1 has no reals, because quic consumed all of em;
  ASSERT_EQ(lb->getRealsForVip(v1).size(), 0);
  // v2 has same reals addresses as quic, so all of was added as well.
  ASSERT_EQ(lb->getRealsForVip(v2).size(), kMaxNumOfReals);
  ASSERT_EQ(lb->getQuicRealsMapping().size(), kMaxNumOfReals);
  action = ModifyAction::DEL;
  // deleting 4k reals
  ASSERT_TRUE(lb->modifyRealsForVip(action, newReals2, v2));
  lb->modifyQuicRealsMapping(action, qReals2);
  ASSERT_EQ(lb->getQuicRealsMapping().size(), 0);
  // retrying to add new rels to v1.
  action = ModifyAction::ADD;
  ASSERT_TRUE(lb->modifyRealsForVip(action, newReals1, v1));
  ASSERT_EQ(lb->getRealsForVip(v1).size(), kMaxNumOfReals);
};

TEST_F(KatranLbTest, testUpdateQuicReal) {
  QuicReal real;
  std::vector<QuicReal> reals;
  ModifyAction action = ModifyAction::ADD;
  real.address = "10.0.0.1";
  real.id = 1;
  reals.push_back(real);

  // adding one mapping
  lb->modifyQuicRealsMapping(action, reals);
  ASSERT_EQ(lb->getQuicRealsMapping().size(), 1);

  // adding same mapping again
  lb->modifyQuicRealsMapping(action, reals);
  ASSERT_EQ(lb->getQuicRealsMapping().size(), 1);

  // adding mapping for same ID but diffrent IP
  reals[0].address = "2.0.0.1";
  lb->modifyQuicRealsMapping(action, reals);
  auto resMap = lb->getQuicRealsMapping();
  ASSERT_EQ(resMap.size(), 1);
  ASSERT_EQ(resMap[0].address, "2.0.0.1");

  // adding mapping for same IP with another ID
  reals[0].id = 2;
  lb->modifyQuicRealsMapping(action, reals);
  resMap = lb->getQuicRealsMapping();
  ASSERT_EQ(resMap.size(), 2);
  ASSERT_EQ(resMap[0].address, "2.0.0.1");
  ASSERT_EQ(resMap[1].address, "2.0.0.1");

  action = ModifyAction::DEL;

  // deleting non existing mapping
  reals[0].id = 100;
  lb->modifyQuicRealsMapping(action, reals);
  ASSERT_EQ(lb->getQuicRealsMapping().size(), 2);

  // deleting existing mapping id but mismatch IP
  reals[0].id = 1;
  reals[0].address = "9.9.9.9";
  lb->modifyQuicRealsMapping(action, reals);
  ASSERT_EQ(lb->getQuicRealsMapping().size(), 2);

  // deleting existing
  reals[0].id = 1;
  reals[0].address = "2.0.0.1";
  QuicReal real2;
  real2.id = 2;
  real2.address = "2.0.0.1";
  reals.emplace_back(real2);
  lb->modifyQuicRealsMapping(action, reals);
  ASSERT_EQ(lb->getQuicRealsMapping().size(), 0);
}

TEST_F(KatranLbTest, getRealsForVip) {
  lb->addVip(v1);
  lb->addRealForVip(r1, v1);
  lb->addRealForVip(r2, v1);
  ASSERT_EQ(lb->getRealsForVip(v1).size(), 2);
};

TEST_F(KatranLbTest, getHealthcheckersDst) {
  lb->addHealthcheckerDst(1, "192.168.1.1");
  lb->addHealthcheckerDst(2, "192.168.1.1");
  auto hcs = lb->getHealthcheckersDst();
  ASSERT_EQ(hcs.size(), 2);
};

TEST_F(KatranLbTest, invalidAddressHandling) {
  VipKey v;
  v.address = "aaa";
  v.port = 0;
  v.proto = 6;
  NewReal r;
  r.address = "bbb";
  r.weight = 1;

  int res;
  // adding incorrect vip
  res = lb->addVip(v);
  ASSERT_FALSE(res);
  // adding correct vip
  res = lb->addVip(v1);
  ASSERT_TRUE(res);
  // adding incorrect real for correct vip
  res = lb->addRealForVip(r, v1);
  auto rnum = lb->getRealsForVip(v1);
  ASSERT_EQ(rnum.size(), 0);
  // adding incorrect hc dst
  res = lb->addHealthcheckerDst(1, "bbb");
  ASSERT_FALSE(res);
  auto stats = lb->getKatranLbStats();
  ASSERT_EQ(stats.addrValidationFailed, 3);
};

TEST_F(KatranLbTest, addInvalidSrcRoutingRule) {
  std::vector<std::string> srcsv4 = {"10.0.0.0/24", "10.0.1.0/24"};
  auto res = lb->addSrcRoutingRule(srcsv4, "asd");
  ASSERT_EQ(res, -1);
  res = lb->addSrcRoutingRule(srcsv4, "fc00::/64");
  ASSERT_EQ(res, -1);
};

TEST_F(KatranLbTest, addValidSrcRoutingRuleV4) {
  std::vector<std::string> srcsv4 = {"10.0.0.0/24", "10.0.1.0/24"};
  auto res = lb->addSrcRoutingRule(srcsv4, "fc00::1");
  ASSERT_EQ(res, 0);
};

TEST_F(KatranLbTest, addValidSrcRoutingRuleV6) {
  std::vector<std::string> srcsv6 = {"fc00:1::/64", "fc00:2::/64"};
  auto res = lb->addSrcRoutingRule(srcsv6, "fc00::1");
  ASSERT_EQ(res, 0);
};

TEST_F(KatranLbTest, addMaxSrcRules) {
  std::vector<std::string> srcs;
  for (int i = 0; i < 20; i++) {
    auto prefix = fmt::format("10.0.{}.0/24", i);
    srcs.push_back(prefix);
  }
  auto res = lb->addSrcRoutingRule(srcs, "fc00::1");
  ASSERT_EQ(res, 10);
  auto src_rules = lb->getSrcRoutingRule();
  ASSERT_EQ(src_rules.size(), 10);
  ASSERT_EQ(lb->getSrcRoutingRuleCidr().size(), 10);
  ASSERT_EQ(lb->getSrcRoutingMap().size(), 10);
  ASSERT_EQ(lb->getNumToRealMap().size(), 1);
  auto src_iter = src_rules.find("10.0.0.0/24");
  ASSERT_TRUE(src_iter != src_rules.end());
  ASSERT_EQ(src_iter->second, "fc00::1");
};

TEST_F(KatranLbTest, delSrcRules) {
  std::vector<std::string> srcs;
  for (int i = 0; i < 10; i++) {
    auto prefix = fmt::format("10.0.{}.0/24", i);
    srcs.push_back(prefix);
  }
  ASSERT_EQ(lb->addSrcRoutingRule(srcs, "fc00::1"), 0);
  ASSERT_EQ(lb->getSrcRoutingRuleSize(), 10);
  ASSERT_TRUE(lb->delSrcRoutingRule(srcs));
  ASSERT_EQ(lb->getSrcRoutingRuleSize(), 0);
};

TEST_F(KatranLbTest, clearSrcRules) {
  std::vector<std::string> srcs;
  for (int i = 0; i < 10; i++) {
    auto prefix = fmt::format("10.0.{}.0/24", i);
    srcs.push_back(prefix);
  }
  ASSERT_EQ(lb->addSrcRoutingRule(srcs, "fc00::1"), 0);
  ASSERT_EQ(lb->getSrcRoutingRuleSize(), 10);
  ASSERT_TRUE(lb->clearAllSrcRoutingRules());
  ASSERT_EQ(lb->getSrcRoutingRuleSize(), 0);
};

TEST_F(KatranLbTest, addFewInvalidNets) {
  std::vector<std::string> srcs;
  for (int i = 0; i < 7; i++) {
    auto prefix = fmt::format("10.0.{}.0/24", i);
    srcs.push_back(prefix);
  }
  srcs.push_back("aaa");
  srcs.push_back("bbb");
  auto res = lb->addSrcRoutingRule(srcs, "fc00::1");
  ASSERT_EQ(res, 2);
  ASSERT_EQ(lb->getSrcRoutingRuleSize(), 7);
};

TEST_F(KatranLbTest, addInvalidDecapDst) {
  ASSERT_FALSE(lb->addInlineDecapDst("asd"));
}

TEST_F(KatranLbTest, addInvalidDecapDstNet) {
  ASSERT_FALSE(lb->addInlineDecapDst("fc00::/64"));
}

TEST_F(KatranLbTest, addValidDecapDst) {
  ASSERT_TRUE(lb->addInlineDecapDst("fc00::1"));
}

TEST_F(KatranLbTest, delValidDecapDst) {
  ASSERT_TRUE(lb->addInlineDecapDst("fc00::1"));
  ASSERT_TRUE(lb->delInlineDecapDst("fc00::1"));
}

TEST_F(KatranLbTest, delInvalidDecapDst) {
  ASSERT_FALSE(lb->delInlineDecapDst("fc00::2"));
}

TEST_F(KatranLbTest, addMaxDecapDst) {
  ASSERT_TRUE(lb->addInlineDecapDst("fc00::1"));
  ASSERT_TRUE(lb->addInlineDecapDst("fc00::2"));
  ASSERT_TRUE(lb->addInlineDecapDst("fc00::3"));
  ASSERT_TRUE(lb->addInlineDecapDst("fc00::4"));
  ASSERT_FALSE(lb->addInlineDecapDst("fc00::5"));
  ASSERT_EQ(lb->getInlineDecapDst().size(), 4);
}

} // namespace katran
