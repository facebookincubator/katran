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

#include <katran/lib/MaglevHashV2.h>

namespace katran {

std::vector<int> MaglevHashV2::generateHashRing(
    std::vector<Endpoint> endpoints,
    const uint32_t ring_size) {
  std::vector<int> result(ring_size, -1);

  if (endpoints.size() == 0) {
    return result;
  } else if (endpoints.size() == 1) {
    for (auto& v : result) {
      v = endpoints[0].num;
    }
    return result;
  }

  auto max_weight = 0;
  for (const auto& endpoint : endpoints) {
    if (endpoint.weight > max_weight) {
      max_weight = endpoint.weight;
    }
  }

  uint32_t runs = 0;
  std::vector<uint32_t> permutation(endpoints.size() * 2, 0);
  std::vector<uint32_t> next(endpoints.size(), 0);
  std::vector<uint32_t> cum_weight(endpoints.size(), 0);

  for (int i = 0; i < endpoints.size(); i++) {
    genMaglevPermutation(permutation, endpoints[i], i, ring_size);
  }

  for (;;) {
    for (int i = 0; i < endpoints.size(); i++) {
      cum_weight[i] += endpoints[i].weight;
      if (cum_weight[i] >= max_weight) {
        cum_weight[i] -= max_weight;
        auto offset = permutation[2 * i];
        auto skip = permutation[2 * i + 1];
        auto cur = (offset + next[i] * skip) % ring_size;
        while (result[cur] >= 0) {
          next[i] += 1;
          cur = (offset + next[i] * skip) % ring_size;
        }
        result[cur] = endpoints[i].num;
        next[i] += 1;
        runs++;
        if (runs == ring_size) {
          return result;
        }
      }
    }
  }
}

} // namespace katran
