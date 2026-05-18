/*
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

#include "katran/lib/MaglevBase.h"

namespace katran {

namespace {

// Helper to call genMaglevPermutation and return (offset, skip) for pos=0.
std::pair<uint32_t, uint32_t>
getPermutation(uint64_t hash, uint32_t pos, uint32_t ring_size) {
  Endpoint ep;
  ep.num = 0;
  ep.weight = 1;
  ep.hash = hash;
  std::vector<uint32_t> perm(2 * (pos + 1), 0);
  MaglevBase::genMaglevPermutation(perm, ep, pos, ring_size);
  return {perm[2 * pos], perm[2 * pos + 1]};
}

} // namespace

TEST(MaglevBaseTest, Determinism) {
  constexpr uint32_t ring_size = 65537;
  auto [offset1, skip1] = getPermutation(/*hash=*/42, /*pos=*/0, ring_size);
  auto [offset2, skip2] = getPermutation(/*hash=*/42, /*pos=*/0, ring_size);
  EXPECT_EQ(offset1, offset2);
  EXPECT_EQ(skip1, skip2);
}

TEST(MaglevBaseTest, SkipAlwaysInRange) {
  constexpr uint32_t ring_size = 65537;
  for (uint64_t hash :
       {UINT64_C(0),
        UINT64_C(1),
        UINT64_C(42),
        UINT64_C(1234567),
        UINT64_MAX}) {
    auto [offset, skip] = getPermutation(hash, /*pos=*/0, ring_size);
    EXPECT_GE(skip, 1u) << "skip=" << skip << " for hash=" << hash;
    EXPECT_LT(skip, ring_size) << "skip=" << skip << " for hash=" << hash;
    (void)offset;
  }
}

TEST(MaglevBaseTest, OffsetAlwaysInRange) {
  constexpr uint32_t ring_size = 65537;
  for (uint64_t hash :
       {UINT64_C(0),
        UINT64_C(1),
        UINT64_C(42),
        UINT64_C(1234567),
        UINT64_MAX}) {
    auto [offset, skip] = getPermutation(hash, /*pos=*/0, ring_size);
    EXPECT_LT(offset, ring_size) << "offset=" << offset << " for hash=" << hash;
    (void)skip;
  }
}

TEST(MaglevBaseTest, PosIndexing) {
  // pos=k writes to permutation[2k] and permutation[2k+1]
  constexpr uint32_t ring_size = 65537;
  constexpr uint32_t n = 4;
  Endpoint ep;
  ep.num = 0;
  ep.weight = 1;
  ep.hash = 99;
  std::vector<uint32_t> perm(2 * n, 0);
  for (uint32_t pos = 0; pos < n; pos++) {
    MaglevBase::genMaglevPermutation(perm, ep, pos, ring_size);
  }
  // Each (offset, skip) pair must be within range.
  for (uint32_t pos = 0; pos < n; pos++) {
    EXPECT_LT(perm[2 * pos], ring_size) << "pos=" << pos;
    EXPECT_GE(perm[2 * pos + 1], 1u) << "pos=" << pos;
    EXPECT_LT(perm[2 * pos + 1], ring_size) << "pos=" << pos;
  }
}

TEST(MaglevBaseTest, DifferentHashesDifferentPermutations) {
  constexpr uint32_t ring_size = 65537;
  auto [off0, skip0] = getPermutation(/*hash=*/0, /*pos=*/0, ring_size);
  auto [off1, skip1] = getPermutation(/*hash=*/1, /*pos=*/0, ring_size);
  // Two distinct hashes should produce distinct (offset, skip) pairs.
  EXPECT_TRUE(off0 != off1 || skip0 != skip1)
      << "hash=0 and hash=1 produced identical permutation entry";
}

TEST(MaglevBaseTest, SmallerRingSize) {
  // Verify invariants hold with a minimal prime ring_size.
  constexpr uint32_t ring_size = 7;
  for (uint64_t hash : {0ULL, 3ULL, 6ULL, 100ULL}) {
    auto [offset, skip] = getPermutation(hash, /*pos=*/0, ring_size);
    EXPECT_LT(offset, ring_size);
    EXPECT_GE(skip, 1u);
    EXPECT_LT(skip, ring_size);
  }
}

} // namespace katran
