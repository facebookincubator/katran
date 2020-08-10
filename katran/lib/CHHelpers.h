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
#include <memory>
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
 * ConsistentHash implements interface, which is used by CHFactory class to
 * generate hash ring
 */
class ConsistentHash {
 public:
  /**
   * @param std::vector<Endpoints>& endpoints, which will be used for CH
   * @param uint32_t ring_size size of the CH ring
   * @return std::vector<int> vector, which describe CH ring.
   */
  virtual std::vector<int> generateHashRing(
      std::vector<Endpoint> endpoints,
      const uint32_t ring_size = kDefaultChRingSize) = 0;

  virtual ~ConsistentHash() = default;
};

enum class HashFunction {
  Maglev,
};

/**
 * This class implements generic helpers to build Consistent hash rings for
 * specified Endpoints.
 */
class CHFactory {
 public:
  /**
   * @param HashFunction func to use for hash ring generation
   */
  static std::unique_ptr<ConsistentHash> make(HashFunction func);
};

} // namespace katran
