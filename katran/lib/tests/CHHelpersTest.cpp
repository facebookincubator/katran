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
#include <vector>

#include "katran/lib/CHHelpers.h"

namespace katran {

constexpr uint32_t nreals = 400;
constexpr uint32_t nreals_diff_weight = 3;

TEST(CHHelpersTest, testMaglevCHSameWeight) {
  std::vector<Endpoint> endpoints;
  std::vector<uint32_t> freq(nreals, 0);
  Endpoint endpoint;

  for (int i = 0; i < nreals; i++) {
    endpoint.num = i;
    endpoint.weight = 1;
    endpoint.hash = i;
    endpoints.push_back(endpoint);
  }

  auto maglev_hashing = CHFactory::make(HashFunction::Maglev);

  auto maglev_ch = maglev_hashing->generateHashRing(endpoints);

  for (int i = 0; i < maglev_ch.size(); i++) {
    // test that we have changed all points inside ch ring
    ASSERT_NE(maglev_ch[i], -1);
    freq[maglev_ch[i]]++;
  }

  std::sort(freq.begin(), freq.end());

  auto diff = freq[freq.size() - 1] - freq[0];
  // testing that when weights are equal and = 1; the diff
  // between max and min frequency is 1 as maglev's doc
  // promised;
  ASSERT_EQ(diff, 1);
}

TEST(CHHelpersTest, testMaglevV2CHSameWeight) {
  std::vector<Endpoint> endpoints;
  std::vector<uint32_t> freq(nreals, 0);
  Endpoint endpoint;

  for (int i = 0; i < nreals; i++) {
    endpoint.num = i;
    endpoint.weight = 1;
    endpoint.hash = i;
    endpoints.push_back(endpoint);
  }

  auto maglev_hashing = CHFactory::make(HashFunction::MaglevV2);

  auto maglev_ch = maglev_hashing->generateHashRing(endpoints);

  for (int i = 0; i < maglev_ch.size(); i++) {
    // test that we have changed all points inside ch ring
    ASSERT_NE(maglev_ch[i], -1);
    freq[maglev_ch[i]]++;
  }

  std::sort(freq.begin(), freq.end());

  auto diff = freq[freq.size() - 1] - freq[0];
  // testing that when weights are equal and = 1; the diff
  // between max and min frequency is 1 as maglev's doc
  // promised;
  ASSERT_EQ(diff, 1);
}

TEST(CHHelpersTest, testMaglevCHDiffWeight) {
  std::vector<Endpoint> endpoints;
  std::vector<uint32_t> freq(nreals_diff_weight, 0);
  Endpoint endpoint;

  for (int i = 0; i < nreals_diff_weight; i++) {
    endpoint.num = i;
    endpoint.weight = 1;
    endpoint.hash = i;
    endpoints.push_back(endpoint);
  }
  endpoints[0].weight = 2;

  auto maglev_hashing = CHFactory::make(HashFunction::Maglev);

  auto maglev_ch = maglev_hashing->generateHashRing(endpoints);

  for (int i = 0; i < maglev_ch.size(); i++) {
    // test that we have changed all points inside ch ring
    ASSERT_NE(maglev_ch[i], -1);
    freq[maglev_ch[i]]++;
  }

  std::sort(freq.begin(), freq.end());

  auto diff = freq[freq.size() - 1] - freq[0];
  // testing that when weights are not equal but the sum is not equal to hash
  // ring size the difference between max and min frequency is equal to 2 (as
  // weight of the biggest element)
  ASSERT_EQ(diff, 2);
}

TEST(CHHelpersTest, testMaglevV2CHDiffWeight) {
  std::vector<Endpoint> endpoints;
  std::vector<uint32_t> freq(nreals_diff_weight, 0);
  Endpoint endpoint;

  for (int i = 0; i < nreals_diff_weight; i++) {
    endpoint.num = i;
    endpoint.weight = 1;
    endpoint.hash = i;
    endpoints.push_back(endpoint);
  }
  endpoints[0].weight = 2;

  auto maglev_hashing = CHFactory::make(HashFunction::MaglevV2);

  auto maglev_ch = maglev_hashing->generateHashRing(endpoints);

  for (int i = 0; i < maglev_ch.size(); i++) {
    // test that we have changed all points inside ch ring
    ASSERT_NE(maglev_ch[i], -1);
    freq[maglev_ch[i]]++;
  }

  std::sort(freq.begin(), freq.end());

  auto diff = freq[freq.size() - 1] - freq[0];
  // testing that when weights are not equal but the sum is not equal to hash
  // ring size the difference between max and min frequency is equal to 2 (as
  // weight of the biggest element)
  ASSERT_EQ(diff, 16385);
}

TEST(CHHelpersTest, testMaglevWeightsSumLargerThanRing) {
  // Illustrate hashing behaviour when sum of all weights exceeds the
  // CH ring size
  std::vector<Endpoint> endpoints;
  std::vector<uint32_t> freq(nreals, 0);
  Endpoint endpoint;
  // Sum of the all endpoint weights will exceed CH ring by factor of 2
  uint32_t weight = (kDefaultChRingSize * 2) / nreals;

  for (int i = 0; i < nreals; i++) {
    endpoint.num = i;
    endpoint.weight = weight;
    endpoint.hash = i;
    endpoints.push_back(endpoint);
  }

  auto maglev_hashing = CHFactory::make(HashFunction::Maglev);

  auto maglev_ch = maglev_hashing->generateHashRing(endpoints);

  for (int i = 0; i < maglev_ch.size(); i++) {
    // test that we have changed all points inside ch ring
    ASSERT_NE(maglev_ch[i], -1);
    freq[maglev_ch[i]]++;
  }

  // Expect only half of the reals to have full slots count
  int realsWithFullSlots = (nreals / 2);
  int realsWithPartailSlots = 1; // 1 real get partial slots
  for (int i = 0; i < freq.size(); i++) {
    if (i < realsWithFullSlots) {
      EXPECT_EQ(freq[i], weight);
    } else if (i < realsWithFullSlots + realsWithPartailSlots) {
      EXPECT_GT(freq[i], 0);
    } else {
      EXPECT_EQ(freq[i], 0);
    }
  }
}

TEST(CHHelpersTest, testMaglevWeightsSumBelowRingSize) {
  // Illustrate hashing behaviour when sum of all weights is slightly below the
  // CH ring size
  std::vector<Endpoint> endpoints;
  std::vector<uint32_t> freq(nreals, 0);
  Endpoint endpoint;
  // Sum of the all endpoint weights is less than nreals from CH ring size
  uint32_t weight = (kDefaultChRingSize / nreals) - 1;

  for (int i = 0; i < nreals; i++) {
    endpoint.num = i;
    endpoint.weight = weight;
    endpoint.hash = i;
    endpoints.push_back(endpoint);
  }

  auto maglev_hashing = CHFactory::make(HashFunction::Maglev);

  auto maglev_ch = maglev_hashing->generateHashRing(endpoints);

  for (int i = 0; i < maglev_ch.size(); i++) {
    // test that we have changed all points inside ch ring
    ASSERT_NE(maglev_ch[i], -1);
    freq[maglev_ch[i]]++;
  }

  std::sort(freq.begin(), freq.end());

  // all reals included with equal frequency
  auto diff = freq[freq.size() - 1] - freq[0];
  EXPECT_EQ(diff, 1);
  // none have 0 frequency (sorted vector)
  EXPECT_GT(freq[0], 0);
}
} // namespace katran
