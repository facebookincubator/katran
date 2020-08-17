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

#include "katran/lib/CHHelpers.h"

namespace katran {

/**
 * MaglevBase class implements Maglev's permutation and should be used as a base
 * class for all versions of Maglev's hashing (more info:
 * http://research.google.com/pubs/pub44824.html ; section 3.4)
 */
class MaglevBase : public ConsistentHash {
 public:
  MaglevBase() {}
  /**
   * @param vector<uint32_t>& container for generated permutations
   * @param Endpoint& endpoint endpoint for which permutation is going to be
   * generated
   * @param uint32_t pos position of specified endpoint
   * @param uint32_t ring_size size of the hash ring
   *
   * helper function which will generate Maglev's permutation array for
   * specified endpoint on specified possition
   */
  static void genMaglevPermutation(
      std::vector<uint32_t>& permutation,
      const Endpoint& endpoint,
      const uint32_t pos,
      const uint32_t ring_size);
};

} // namespace katran
