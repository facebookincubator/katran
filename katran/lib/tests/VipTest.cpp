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

#include <gtest/gtest.h>
#include <algorithm>
#include <iostream>

#include "katran/lib/Vip.h"

namespace katran {

class VipTestF : public ::testing::Test {
 protected:
  VipTestF()
      : vip1(1),
        vip2(2, 0, kDefaultChRingSize, HashFunction::MaglevV2),
        reals(100) {}

  void SetUp() override {
    UpdateReal ureal;
    ureal.action = ModifyAction::ADD;

    for (int i = 0; i < 100; i++) {
      ureal.updatedReal.num = i;
      ureal.updatedReal.weight = 10;
      ureal.updatedReal.hash = i;
      reals[i] = ureal;
    }
  }

  Vip vip1;
  Vip vip2;
  std::vector<UpdateReal> reals;
};

TEST_F(VipTestF, testBatchUpdateReals) {
  // new ch ring, the size of the delta is equal to ring_size
  auto delta = vip1.batchRealsUpdate(reals);
  auto delta2 = vip2.batchRealsUpdate(reals);
  ASSERT_EQ(delta.size(), vip1.getChRingSize());
  ASSERT_EQ(delta2.size(), vip2.getChRingSize());

  // same batch of reals w/ same actions shouldn't generate any delta
  delta = vip1.batchRealsUpdate(reals);
  delta2 = vip2.batchRealsUpdate(reals);
  ASSERT_EQ(delta.size(), 0);
  ASSERT_EQ(delta2.size(), 0);

  delta = vip1.delReal(0);
  delta2 = vip2.delReal(0);
  ASSERT_EQ(delta.size(), 1009);
  ASSERT_EQ(delta2.size(), 1020);
}

TEST_F(VipTestF, testBatchUpdateRealsWeight) {
  // new ch ring, the size of the delta is equal to ring_size
  auto delta = vip1.batchRealsUpdate(reals);
  auto delta2 = vip2.batchRealsUpdate(reals);
  ASSERT_EQ(delta.size(), vip1.getChRingSize());
  ASSERT_EQ(delta2.size(), vip2.getChRingSize());

  // same batch of reals w/ same actions shouldn't generate any delta
  delta = vip1.batchRealsUpdate(reals);
  delta2 = vip2.batchRealsUpdate(reals);
  ASSERT_EQ(delta.size(), 0);
  ASSERT_EQ(delta2.size(), 0);

  for (auto& real : reals) {
    real.updatedReal.weight = 13;
  }

  delta = vip1.batchRealsUpdate(reals);
  delta2 = vip2.batchRealsUpdate(reals);
  ASSERT_EQ(delta.size(), 17);
  ASSERT_EQ(delta2.size(), 0);

  reals[0] = UpdateReal{ModifyAction::ADD, {0, 26, 0}};
  delta = vip1.batchRealsUpdate(reals);
  delta2 = vip2.batchRealsUpdate(reals);
  ASSERT_EQ(delta.size(), 109);
  ASSERT_EQ(delta2.size(), 1013);
}

TEST(VipTest, testAddRemoveReal) {
  Vip vip1(1);
  Endpoint real;
  real.num = 0;
  real.weight = 1;
  real.hash = 0;
  auto delta = vip1.addReal(real);
  ASSERT_EQ(delta.size(), vip1.getChRingSize());
  real.num = 1;
  real.hash = 1;
  delta = vip1.addReal(real);
  ASSERT_EQ(delta.size(), 32768);
  delta = vip1.delReal(1);
  ASSERT_EQ(delta.size(), 32768);
  // removing non-existing real
  delta = vip1.delReal(1);
  ASSERT_EQ(delta.size(), 0);
}

TEST_F(VipTestF, testGetRealsAndWeight) {
  vip1.batchRealsUpdate(reals);
  auto endpoints = vip1.getRealsAndWeight();
  ASSERT_EQ(endpoints.size(), 100);
  for (auto& real : endpoints) {
    ASSERT_EQ(real.weight, 10);
  }
}

TEST_F(VipTestF, testGetReals) {
  auto delta = vip1.batchRealsUpdate(reals);
  auto vip_reals = vip1.getReals();
  ASSERT_EQ(vip_reals.size(), 100);
  ASSERT_EQ(delta.size(), 65537);
  delta = vip1.batchRealsUpdate(reals);
  ASSERT_EQ(delta.size(), 0);
  delta = vip1.recalculateHashRing();
  ASSERT_EQ(delta.size(), 0);
}

} // namespace katran
