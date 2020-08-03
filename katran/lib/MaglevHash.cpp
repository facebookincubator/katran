#include <katran/lib/MaglevHash.h>
#include "katran/lib/MurmurHash3.h"

namespace katran {

namespace {
constexpr uint32_t kHashSeed0 = 0;
constexpr uint32_t kHashSeed1 = 2307;
constexpr uint32_t kHashSeed2 = 42;
constexpr uint32_t kHashSeed3 = 2718281828;
} // namespace

void MaglevHash::genMaglevPermuation(
    std::vector<uint32_t>& permutation,
    const Endpoint endpoint,
    const uint32_t pos,
    const uint32_t ring_size) {
  auto offset_hash = MurmurHash3_x64_64(endpoint.hash, kHashSeed2, kHashSeed0);

  auto offset = offset_hash % ring_size;

  auto skip_hash = MurmurHash3_x64_64(endpoint.hash, kHashSeed3, kHashSeed1);

  auto skip = (skip_hash % (ring_size - 1)) + 1;

  permutation[2 * pos] = offset;
  permutation[2 * pos + 1] = skip;
};

std::vector<int> MaglevHash::generateHashRing(
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

  uint32_t runs = 0;
  std::vector<uint32_t> permutation(endpoints.size() * 2, 0);
  std::vector<uint32_t> next(endpoints.size(), 0);

  for (int i = 0; i < endpoints.size(); i++) {
    genMaglevPermuation(permutation, endpoints[i], i, ring_size);
  }

  for (;;) {
    for (int i = 0; i < endpoints.size(); i++) {
      auto offset = permutation[2 * i];
      auto skip = permutation[2 * i + 1];
      // our realization of "weights" for maglev's hash.
      for (int j = 0; j < endpoints[i].weight; j++) {
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
      endpoints[i].weight = 1;
    }
  }
};

} // namespace katran
