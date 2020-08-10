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

} // namespace katran
