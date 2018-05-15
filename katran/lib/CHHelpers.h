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

#pragma once

#include <cstdint>
#include <vector>

namespace katran {

constexpr uint32_t kDefaultChRingSize = 65537;

/**
 * struct which describes backend, each backend would have unique number,
 * weight (the measurment of how often we would see this endpoint
 * on CH ring) and hash value, which will be used as a seed value
 * (it should be unique value per endpoint for CH to work as expected)
 */
struct Endpoint {
  uint32_t num;
  uint32_t weight;
  uint64_t hash;
};

/**
 * This class implements generic helpers to build Consisten hash rings for
 * specified Endpoints.
 */
class CHHelpers {
 public:
  /**
   * @param std::vector<Endpoints>& endpoints, which will be used for CH
   * @param uint32_t ring_size size of the CH ring
   * @return std::vector<int> vector, which describe CH ring.
   * it's size would be ring_size and
   * which will have Endpoints.num as a values.
   *
   * this helper function would implement Maglev's hash algo
   * (more info: http://research.google.com/pubs/pub44824.html ; section 3.4)
   * ring_size must be prime number.
   * this function could throw because allocation for vector could fail.
   */
  static std::vector<int> GenerateMaglevHash(
      std::vector<Endpoint> endpoints,
      const uint32_t ring_size = kDefaultChRingSize);

 private:
  /**
   * helper function which will generate Maglev's permutation array for
   * specified endpoint on specified possition
   */
  static void genMaglevPermuation(
      std::vector<uint32_t>& permutation,
      const Endpoint endpoint,
      const uint32_t pos,
      const uint32_t ring_size);
};

} // namespace katran
