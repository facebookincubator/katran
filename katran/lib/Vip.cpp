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

#include "Vip.h"

#include <algorithm>

namespace katran {

bool compareEndpoints(const Endpoint& a, const Endpoint& b) {
  return a.hash < b.hash;
}

Vip::Vip(
    uint32_t vipNum,
    uint32_t vipFlags,
    uint32_t ringSize,
    HashFunction func)
    : vipNum_(vipNum),
      vipFlags_(vipFlags),
      chRingSize_(ringSize),
      chRing_(ringSize, -1) {
  chash = CHFactory::make(func);
}

void Vip::setHashFunction(HashFunction func) {
  chash = CHFactory::make(func);
}

std::vector<RealPos> Vip::calculateHashRing(std::vector<Endpoint> endpoints) {
  std::vector<RealPos> delta;
  RealPos new_pos;
  if (endpoints.size() != 0) {
    auto new_ch_ring = chash->generateHashRing(endpoints, chRingSize_);

    // compare new and old ch rings. send back only delta between em.
    for (int i = 0; i < chRingSize_; i++) {
      if (new_ch_ring[i] != chRing_[i]) {
        new_pos.pos = i;
        new_pos.real = new_ch_ring[i];
        delta.push_back(new_pos);
        chRing_[i] = new_ch_ring[i];
      }
    }
  }
  return delta;
}

std::vector<RealPos> Vip::batchRealsUpdate(std::vector<UpdateReal>& ureals) {
  auto endpoints = getEndpoints(ureals);
  return calculateHashRing(endpoints);
}

std::vector<RealPos> Vip::recalculateHashRing() {
  auto reals = getRealsAndWeight();
  return calculateHashRing(reals);
}

std::vector<RealPos> Vip::addReal(Endpoint real) {
  std::vector<UpdateReal> reals;
  UpdateReal ureal;
  ureal.action = ModifyAction::ADD;
  ureal.updatedReal = real;
  reals.push_back(ureal);
  return batchRealsUpdate(reals);
}

std::vector<RealPos> Vip::delReal(uint32_t realNum) {
  std::vector<UpdateReal> reals;
  UpdateReal ureal;
  ureal.action = ModifyAction::DEL;
  ureal.updatedReal.num = realNum;
  reals.push_back(ureal);
  return batchRealsUpdate(reals);
}

std::vector<uint32_t> Vip::getReals() {
  std::vector<uint32_t> realNums(reals_.size());
  int i = 0;
  for (auto& r : reals_) {
    realNums[i++] = r.first;
  }
  return realNums;
}

std::vector<Endpoint> Vip::getRealsAndWeight() {
  std::vector<Endpoint> endpoints(reals_.size());
  Endpoint endpoint;
  int i = 0;
  for (auto& r : reals_) {
    endpoint.num = r.first;
    endpoint.weight = r.second.weight;
    endpoint.hash = r.second.hash;
    endpoints[i++] = endpoint;
  }
  std::sort(endpoints.begin(), endpoints.end(), compareEndpoints);
  return endpoints;
}

std::vector<Endpoint> Vip::getEndpoints(std::vector<UpdateReal>& ureals) {
  Endpoint endpoint;
  std::vector<Endpoint> endpoints;
  bool reals_changed = false;

  for (auto& ureal : ureals) {
    if (ureal.action == ModifyAction::DEL) {
      reals_.erase(ureal.updatedReal.num);
      reals_changed = true;
    } else {
      auto cur_weight = reals_[ureal.updatedReal.num].weight;
      if (cur_weight != ureal.updatedReal.weight) {
        reals_[ureal.updatedReal.num].weight = ureal.updatedReal.weight;
        reals_[ureal.updatedReal.num].hash = ureal.updatedReal.hash;
        reals_changed = true;
      }
    }
  }

  if (reals_changed) {
    for (auto& real : reals_) {
      // skipping 0 weight
      if (real.second.weight != 0) {
        endpoint.num = real.first;
        endpoint.weight = real.second.weight;
        endpoint.hash = real.second.hash;
        endpoints.push_back(endpoint);
      }
    }
    std::sort(endpoints.begin(), endpoints.end(), compareEndpoints);
  }
  return endpoints;
}

} // namespace katran
