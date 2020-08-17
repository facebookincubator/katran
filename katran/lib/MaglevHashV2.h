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

#pragma once

#include <cstdint>
#include <vector>

#include "katran/lib/MaglevBase.h"

namespace katran {

/**
 * MaglevHashV2 class implements another version of Maglev's hash which does not
 * require the sum of all weights to be equal to the size of the hash ring.
 */
class MaglevHashV2 : public MaglevBase {
 public:
  MaglevHashV2() {}
  /**
   * @param std::vector<Endpoints>& endpoints, which will be used for CH
   * @param uint32_t ring_size size of the CH ring
   * @return std::vector<int> vector, which describe CH ring.
   * it's size would be ring_size and
   * which will have Endpoints.num as a values.
   * ring_size must be prime number.
   * this function could throw because allocation for vector could fail.
   */
  std::vector<int> generateHashRing(
      std::vector<Endpoint>,
      const uint32_t ring_size = kDefaultChRingSize) override;
};

} // namespace katran
