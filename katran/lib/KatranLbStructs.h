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
#include <functional>
#include <string>
#include <vector>

namespace katran {

namespace {
constexpr uint32_t kDefaultKatranPos = 2;
constexpr uint32_t kDefaultMaxVips = 512;
constexpr uint32_t kDefaultMaxReals = 4096;
constexpr uint32_t kDefaultPriority = 2307;
constexpr uint32_t kLbDefaultChRingSize = 65537;
constexpr uint32_t kDefaultMaxLpmSrcSize = 3000000;
constexpr uint32_t kDefaultMaxDecapDstSize = 6;
constexpr unsigned int kDefaultLruSize = 8000000;
constexpr uint32_t kNoFlags = 0;
std::string kNoExternalMap = "";
std::string kDefaultHcInterface = "";
} // namespace

/**
 * struct with meta info for real
 */
struct RealMeta {
  /**
   *vip's number
   */
  uint32_t num;

  /**
   * one real could be used by multiple vips
   * we will delete real (recycle it's num),
   * only when refcount would be equal to zero
   */
  uint32_t refCount;
};

/**
 * information about new real
 */

struct NewReal {
  std::string address;
  uint32_t weight;
};

/**
 * information about quic's real
 */
struct QuicReal {
  std::string address;
  uint32_t id;
};

/**
 * types of address
 */
enum class AddressType {
  INVALID,
  HOST,
  NETWORK,
};

/**
 * struct which contains all configurations for KatranLB
 * @param string mainInterface name where to attach bpf prog (e.g eth0)
 * @param string v4TunInterface name for ipip encap (for healtchecks)
 * @param string v6TunInterface name for ip(6)ip6 encap (for healthchecks)
 * @param string balancerProgPath path to bpf prog for balancer
 * @param string healthcheckingProgPath path to bpf prog for healthchecking
 * @param std::vector<uint8_t> defaultMac mac address of default router
 * @param uint32_t tc priority of healtchecking task
 * @param string rootMapPath path to pinned map from root xdp prog
 * @param rootMapPos position inside rootMap
 * @param bool enableHc flag, is set - we will load healthchecking bpf prog
 * @param uint32_t maxVips maximum allowed vips to configure
 * @param uint32_t maxReals maximum allowed reals to configure
 * @param uint32_t chRingSize size of ch ring for each real
 * @param bool testing flag, if true - don't program forwarding
 * @param uint64_t LruSize size of connection table
 * @param std::vector<int32_t> forwardingCores responsible for forwarding
 * @param std::vector<int32_t> numaNodes mapping of cores to NUMA nodes
 * @param uint32_t maxLpmSrcSize maximum size of map for src based routing
 * @param uint32_t maxDecapDst maximum number of destinations for inline decap
 * @param std::string hcInterface interface where we want to attach hc bpf prog
 *
 * note about rootMapPath and rootMapPos:
 * katran has two modes of operation.
 * the first one is "standalone":
 * when it register itself as one and only xdp prog; this is
 * default. for this mode to work rootMapPath must be equal to "".
 * and we dont evaluate rootMapPos (so it could be any value).
 *
 * the second mode of operation - "shared" -
 * is when we have root xdp prog: which is
 * just doing bpf_tail_call for other xdp's progs, which must registers
 * (put their fd's into predifiened position inside rootMap).
 * in this case rootMapPath must be path to "pinned" map, which has been
 * used by root xdp prog, and rootMapPos is a position (index) of
 * katran's fd inside this map.
 *
 * by default, if hcInterface is not specified we are going to attach
 * healthchecking bpf program to the mainInterfaces
 */
struct KatranConfig {
  std::string mainInterface;
  std::string v4TunInterface;
  std::string v6TunInterface;
  std::string balancerProgPath;
  std::string healthcheckingProgPath;
  std::vector<uint8_t> defaultMac;
  uint32_t priority = kDefaultPriority;
  std::string rootMapPath = kNoExternalMap;
  uint32_t rootMapPos = kDefaultKatranPos;
  bool enableHc = true;
  uint32_t maxVips = kDefaultMaxVips;
  uint32_t maxReals = kDefaultMaxReals;
  uint32_t chRingSize = kLbDefaultChRingSize;
  bool testing = false;
  uint64_t LruSize = kDefaultLruSize;
  std::vector<int32_t> forwardingCores;
  std::vector<int32_t> numaNodes;
  uint32_t maxLpmSrcSize = kDefaultMaxLpmSrcSize;
  uint32_t maxDecapDst = kDefaultMaxDecapDstSize;
  std::string hcInterface = kDefaultHcInterface;
  uint32_t xdpAttachFlags = kNoFlags;
};

/**
 * class which identifies vip
 */

class VipKey {
 public:
  std::string address;
  uint16_t port;
  uint8_t proto;

  bool operator==(const VipKey& other) const {
    return (
        address == other.address && port == other.port && proto == other.proto);
  };
};

struct VipKeyHasher {
  std::size_t operator()(const VipKey& k) const {
    return ((std::hash<std::string>()(k.address) ^
             (std::hash<uint16_t>()(k.port) << 1)) >>
            1) ^
        (std::hash<uint8_t>()(k.proto) << 1);
  };
};

} // namespace katran
