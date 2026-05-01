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

#include "katran/lib/MurmurHash3.h"

namespace katran {

// Seeds used by MaglevBase::genMaglevPermutation.
constexpr uint32_t kMaglevSeed0 = 0;
constexpr uint32_t kMaglevSeed1 = 2307;
constexpr uint64_t kMaglevSeed2 = 42;
constexpr uint64_t kMaglevSeed3 = 2718281828ULL;

TEST(MurmurHash3Test, Deterministic) {
  // Same inputs must always produce the same output.
  constexpr uint64_t a = 0xDEADBEEFCAFEBABEULL;
  EXPECT_EQ(
      MurmurHash3_x64_64(a, kMaglevSeed2, kMaglevSeed0),
      MurmurHash3_x64_64(a, kMaglevSeed2, kMaglevSeed0));
}

TEST(MurmurHash3Test, DistinctSeedsProduceDistinctHashes) {
  // Changing the seed changes the output — critical for Maglev's two
  // independent permutation streams (offset uses seed 0, skip uses seed 2307).
  constexpr uint64_t endpoint_hash = 0x123456789ABCDEF0ULL;
  EXPECT_NE(
      MurmurHash3_x64_64(endpoint_hash, kMaglevSeed2, kMaglevSeed0),
      MurmurHash3_x64_64(endpoint_hash, kMaglevSeed2, kMaglevSeed1));
}

TEST(MurmurHash3Test, DistinctBArgsProduceDistinctHashes) {
  // Changing B changes the output — offset and skip use different B values
  // (kHashSeed2=42 vs kHashSeed3=2718281828) so they must not collide.
  constexpr uint64_t endpoint_hash = 0x123456789ABCDEF0ULL;
  EXPECT_NE(
      MurmurHash3_x64_64(endpoint_hash, kMaglevSeed2, kMaglevSeed0),
      MurmurHash3_x64_64(endpoint_hash, kMaglevSeed3, kMaglevSeed0));
}

TEST(MurmurHash3Test, DistinctAArgsProduceDistinctHashes) {
  // Changing A changes the output, so different endpoint hashes map to
  // different Maglev permutations.
  EXPECT_NE(
      MurmurHash3_x64_64(1, kMaglevSeed2, kMaglevSeed0),
      MurmurHash3_x64_64(2, kMaglevSeed2, kMaglevSeed0));
}

TEST(MurmurHash3Test, ZeroInputsProduceNonZeroOutput) {
  // Finalization mixes in constants, so (0, 0, 0) must not hash to 0.
  EXPECT_NE(MurmurHash3_x64_64(0, 0, 0), 0ULL);
}

} // namespace katran
