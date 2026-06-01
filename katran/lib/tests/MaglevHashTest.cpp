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

#include "katran/lib/MaglevHash.h"
#include "katran/lib/MaglevHashV2.h"

namespace katran {

namespace {

constexpr uint32_t kSmallRing = 7; // smallest useful prime
constexpr uint32_t kMedRing = 11;

Endpoint makeEndpoint(uint32_t num, uint32_t weight, uint64_t hash) {
  return Endpoint{num, weight, hash};
}

} // namespace

// ---- MaglevHash (V1) ----

TEST(MaglevHashTest, EmptyEndpointsAllNegativeOne) {
  MaglevHash hasher;
  const auto ring = hasher.generateHashRing({}, kSmallRing);
  const std::vector<int> expected(kSmallRing, -1);
  EXPECT_EQ(ring, expected);
}

TEST(MaglevHashTest, SingleEndpointFillsRing) {
  MaglevHash hasher;
  const auto ring =
      hasher.generateHashRing({makeEndpoint(5, 1, 42)}, kSmallRing);
  const std::vector<int> expected(kSmallRing, 5);
  EXPECT_EQ(ring, expected);
}

TEST(MaglevHashTest, TwoEndpointsNoHoles) {
  MaglevHash hasher;
  const std::vector<Endpoint> eps = {
      makeEndpoint(0, 1, 1000), makeEndpoint(1, 1, 2000)};
  const auto ring = hasher.generateHashRing(eps, kSmallRing);
  ASSERT_EQ(ring.size(), kSmallRing);
  for (int slot : ring) {
    EXPECT_TRUE(slot == 0 || slot == 1) << "unexpected slot value: " << slot;
  }
}

TEST(MaglevHashTest, Determinism) {
  MaglevHash hasher;
  const std::vector<Endpoint> eps = {
      makeEndpoint(0, 1, 111), makeEndpoint(1, 2, 222)};
  const auto ring1 = hasher.generateHashRing(eps, kMedRing);
  const auto ring2 = hasher.generateHashRing(eps, kMedRing);
  EXPECT_EQ(ring1, ring2);
}

TEST(MaglevHashTest, HigherWeightGetsMoreSlots) {
  // V1: endpoint 0 (weight=2) makes 2 picks in the first round before
  // resetting to 1, so it receives more slots than endpoint 1 (weight=1).
  // With ring_size=7 and 2 endpoints this gives 4 vs 3 slots regardless of
  // hash values.
  MaglevHash hasher;
  const std::vector<Endpoint> eps = {
      makeEndpoint(0, 2, 1000), makeEndpoint(1, 1, 2000)};
  const auto ring = hasher.generateHashRing(eps, kSmallRing);
  const auto count0 = std::count(ring.begin(), ring.end(), 0);
  const auto count1 = std::count(ring.begin(), ring.end(), 1);
  EXPECT_GT(count0, count1);
}

// ---- MaglevHashV2 ----

TEST(MaglevHashV2Test, EmptyEndpointsAllNegativeOne) {
  MaglevHashV2 hasher;
  const auto ring = hasher.generateHashRing({}, kSmallRing);
  const std::vector<int> expected(kSmallRing, -1);
  EXPECT_EQ(ring, expected);
}

TEST(MaglevHashV2Test, SingleEndpointFillsRing) {
  MaglevHashV2 hasher;
  const auto ring =
      hasher.generateHashRing({makeEndpoint(3, 1, 99)}, kSmallRing);
  const std::vector<int> expected(kSmallRing, 3);
  EXPECT_EQ(ring, expected);
}

TEST(MaglevHashV2Test, TwoEndpointsNoHoles) {
  MaglevHashV2 hasher;
  const std::vector<Endpoint> eps = {
      makeEndpoint(0, 1, 1000), makeEndpoint(1, 1, 2000)};
  const auto ring = hasher.generateHashRing(eps, kSmallRing);
  ASSERT_EQ(ring.size(), kSmallRing);
  for (int slot : ring) {
    EXPECT_TRUE(slot == 0 || slot == 1) << "unexpected slot value: " << slot;
  }
}

TEST(MaglevHashV2Test, Determinism) {
  MaglevHashV2 hasher;
  const std::vector<Endpoint> eps = {
      makeEndpoint(0, 1, 111), makeEndpoint(1, 2, 222)};
  const auto ring1 = hasher.generateHashRing(eps, kMedRing);
  const auto ring2 = hasher.generateHashRing(eps, kMedRing);
  EXPECT_EQ(ring1, ring2);
}

TEST(MaglevHashV2Test, HigherWeightGetsMoreSlots) {
  // V2: cumulative weight fires endpoint when sum >= max_weight.
  // With weights [2, 1] and ring_size=7: endpoint 0 fires every iteration,
  // endpoint 1 fires every other iteration, yielding 5 vs 2 slots.
  MaglevHashV2 hasher;
  const std::vector<Endpoint> eps = {
      makeEndpoint(0, 2, 1000), makeEndpoint(1, 1, 2000)};
  const auto ring = hasher.generateHashRing(eps, kSmallRing);
  const auto count0 = std::count(ring.begin(), ring.end(), 0);
  const auto count1 = std::count(ring.begin(), ring.end(), 1);
  EXPECT_GT(count0, count1);
}

TEST(MaglevHashV2Test, V2ProducesDifferentRingThanV1ForUnequalWeights) {
  // V1 and V2 use different weight-accumulation mechanics: V1 repeats endpoint
  // picks within a round then resets to weight=1, while V2 uses a cumulative
  // counter. With weights [2, 1] and ring_size=7, V1 yields 4 vs 3 slots
  // and V2 yields 5 vs 2 slots, so the rings must differ.
  const std::vector<Endpoint> eps = {
      makeEndpoint(0, 2, 1000), makeEndpoint(1, 1, 2000)};
  MaglevHash v1;
  MaglevHashV2 v2;
  const auto ring_v1 = v1.generateHashRing(eps, kSmallRing);
  const auto ring_v2 = v2.generateHashRing(eps, kSmallRing);
  EXPECT_NE(ring_v1, ring_v2);
}

} // namespace katran
