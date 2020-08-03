#pragma once

#include <cstdint>
#include <vector>

#include "katran/lib/CHHelpers.h"

namespace katran {

/**
 * MaglevHash class implements Maglev's hash algo
 * (more info: http://research.google.com/pubs/pub44824.html ; section 3.4)
 */
class MaglevHash : public ConsistentHash {
 public:
  MaglevHash(){};
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
