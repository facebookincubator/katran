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
#include <unordered_map>
#include <vector>

#include "katran/lib/CHHelpers.h"

namespace katran {

/**
 * This struct show on which position real w/ specified opaque id should be
 * located on ch ring.
 */
struct RealPos {
  uint32_t real;
  uint32_t pos;
};

enum class ModifyAction {
  ADD,
  DEL,
};

struct UpdateReal {
  ModifyAction action;
  Endpoint updatedReal;
};

/**
 * struct which is used by Vip class to store real's related metadata
 * such as real's weight and hash
 */
struct VipRealMeta {
  uint32_t weight;
  uint64_t hash;
};

/**
 * this class implements Vip's object and all related methods.
 * such ass add/delete/reals, modify flags, etc.
 */
class Vip {
 public:
  Vip() = delete;

  explicit Vip(
      uint32_t vipNum,
      uint32_t vipFlags = 0,
      uint32_t ringSize = kDefaultChRingSize,
      HashFunction func = HashFunction::Maglev);

  /**
   * getters
   */
  uint32_t getVipNum() const {
    return vipNum_;
  }

  uint32_t getVipFlags() const {
    return vipFlags_;
  }

  uint32_t getChRingSize() const {
    return chRingSize_;
  }

  /**
   * @param uint32_t flags to set
   *
   * helper function to set vip specific flags (such as "don't use lru")
   */
  void setVipFlags(const uint32_t flags) {
    vipFlags_ |= flags;
  }

  /**
   *
   * helper function to clear/unset all flags for vip
   */
  void clearVipFlags() {
    vipFlags_ = 0;
  }

  /**
   * @param uint32_t flags to unset
   *
   * helper function to unset specified flags for vip
   */
  void unsetVipFlags(const uint32_t flags) {
    vipFlags_ &= ~flags;
  }

  /**
   *
   * helper function to return all reals, which has been configured for
   * specified vip (we will return real's opaque id)
   */
  std::vector<uint32_t> getReals();

  /**
   *
   * helper function to return all reals (their opaque ids) and their weight
   */
  std::vector<Endpoint> getRealsAndWeight();

  /**
   * @param Endpoint real which we want to add
   * @return vector<RealPos> delta (in terms of real's position) for ch ring
   *
   * helper function to add new real (w/ specified weight) to ch ring.
   */
  std::vector<RealPos> addReal(Endpoint real);

  /**
   * @param uint32_t real which we want to delete
   * @return vector<RealPos> delta (in terms of real's position) for ch ring
   *
   * helper function to delete real from ch ring.
   */
  std::vector<RealPos> delReal(uint32_t realNum);

  /**
   * @param vector<UpdateReal> vector of reals which we want to update
   * @return vector<RealPos> delta (in terms of real's position) for ch ring
   *
   * helper function to delete and add reals in batch.
   */
  std::vector<RealPos> batchRealsUpdate(std::vector<UpdateReal>& ureals);

  /**
   * @param HashFunction hash function to use for hash ring generation
   *
   * helper, which allows to change hashing functiong for hash ring generation
   */
  void setHashFunction(HashFunction func);

  /**
   * @return vector<RealPos> delta (in terms of real's position) for ch ring
   *
   * helper function which recalculates hash ring for the Vip
   */
  std::vector<RealPos> recalculateHashRing();

 private:
  /**
   * helper function which will modify reals_ and return vector of reals after
   * this modification
   */
  std::vector<Endpoint> getEndpoints(std::vector<UpdateReal>& ureals);

  /**
   * helper function to calculate hash ring and return delta
   */
  std::vector<RealPos> calculateHashRing(std::vector<Endpoint> endpoints);

  /**
   * number which uniquely identifies this vip
   * (also used as an index inside forwarding table)
   */
  uint32_t vipNum_;

  /**
   * vip related flags (such as "dont use src port for hashing" etc)
   */
  uint32_t vipFlags_;

  /**
   * size of ch ring
   */
  uint32_t chRingSize_;

  /**
   * map of reals (theirs opaque id). the value is a real's related
   * metadata (weight and per real hash value).
   */
  std::unordered_map<uint32_t, VipRealMeta> reals_;

  /**
   * ch ring which is used for this vip. we are going to use it
   * for delta computation (between old and new ch rings)
   */
  std::vector<int> chRing_;

  /**
   * hash function to generate hash ring
   */
  std::unique_ptr<ConsistentHash> chash;
};

} // namespace katran
