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

#include <katran/lib/MaglevBase.h>
#include "katran/lib/MurmurHash3.h"

namespace katran {

namespace {
constexpr uint32_t kHashSeed0 = 0;
constexpr uint32_t kHashSeed1 = 2307;
constexpr uint32_t kHashSeed2 = 42;
constexpr uint32_t kHashSeed3 = 2718281828;
} // namespace

void MaglevBase::genMaglevPermutation(
    std::vector<uint32_t>& permutation,
    const Endpoint& endpoint,
    const uint32_t pos,
    const uint32_t ring_size) {
  auto offset_hash = MurmurHash3_x64_64(endpoint.hash, kHashSeed2, kHashSeed0);

  auto offset = offset_hash % ring_size;

  auto skip_hash = MurmurHash3_x64_64(endpoint.hash, kHashSeed3, kHashSeed1);

  auto skip = (skip_hash % (ring_size - 1)) + 1;

  permutation[2 * pos] = offset;
  permutation[2 * pos + 1] = skip;
}

} // namespace katran
