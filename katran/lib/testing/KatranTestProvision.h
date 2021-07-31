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
#include <string>
#include <vector>
#include "katran/lib/KatranLb.h"
#include "katran/lib/KatranLbStructs.h"

namespace katran {
namespace testing {
extern const std::string kMainInterface;
extern const std::string kV4TunInterface;
extern const std::string kV6TunInterface;
extern const std::string kNoExternalMap;
extern const std::vector<uint8_t> kDefaultMac;
extern const std::vector<uint8_t> kLocalMac;
constexpr uint32_t kDefaultPriority = 2307;
constexpr uint32_t kDefaultKatranPos = 8;
constexpr uint32_t kMonitorLimit = 1024;
constexpr bool kNoHc = false;
constexpr uint32_t k1Mbyte = 1024 * 1024;
extern const std::vector<std::string> kReals;

constexpr uint16_t kVipPort = 80;
constexpr uint8_t kUdp = 17;
constexpr uint8_t kTcp = 6;
constexpr uint32_t kDefaultWeight = 1;
constexpr uint32_t kDportHash = 8;
constexpr uint32_t kQuicVip = 4;
constexpr uint32_t kSrcRouting = 16;
constexpr uint32_t kLocalVip = 32;
constexpr uint8_t kLocalReal = 2;

// Each of the TestMode correspond to the TestFixtures
enum class TestMode : uint8_t {
    // Test mode by default, encap mode: IPinIP
    DEFAULT = 0,
    // Tests with GUE encap mode, requires enabling of -DGUE_ENCAP
    GUE = 1,
    // Tests for server_id based routing of TCP packets.
    // Requires enabling of -DTCP_SERVER_ID_ROUTING
    TPR = 2
};

// commonly used counters to check against expected values
enum class KatranTestCounters : uint8_t {
  DEFAULT_NO_COUNTER = 0,
  TOTAL_PKTS = 1,
  LRU_MISSES = 2,
  TCP_SYNS = 3,
  NON_SYN_LRU_MISSES = 4,
  LRU_FALLBACK_HITS = 5,
  QUIC_ROUTING_WITH_CH = 6,
  QUIC_ROUTING_WITH_CID = 7,
  QUIC_CID_V1 = 8,
  QUIC_CID_V2 = 9,
  QUIC_CID_DROPS_REAL_0 = 10,
  QUIC_CID_DROPS_NO_REAL = 11,
  TCP_SERVER_ID_ROUNTING = 12,
  TCP_SERVER_ID_ROUTING_FALLBACK_CH = 13,
  TOTAL_FAILED_BPF_CALLS = 14,
  TOTAL_ADDRESS_VALIDATION_FAILED = 15,
  // optional counters
  ICMP_V4_COUNTS = 16,
  ICMP_V6_COUNTS = 17,
  SRC_ROUTING_PKTS_LOCAL = 18,
  SRC_ROUTING_PKTS_REMOTE = 19,
  INLINE_DECAP_PKTS = 20,
};

struct KatranTestParam {
  TestMode mode{TestMode::DEFAULT};
  std::vector<std::pair<std::string, std::string>> inputData;
  std::vector<std::pair<std::string, std::string>> outputData;
  // expected packets and bytes per Real
  const std::vector<::katran::lb_stats> expectedRealStats() noexcept;
  uint64_t expectedTotalPktsForVip(const katran::VipKey& vip) noexcept;
  uint64_t expectedTotalBytesForVip(const katran::VipKey& vip) noexcept;
  uint64_t expectedTotalPkts() noexcept;
  uint64_t expectedTotalLruMisses() noexcept;
  uint64_t expectedTotalTcpSyns() noexcept;
  uint64_t expectedTotalTcpNonSynLruMisses() noexcept;
  uint64_t expectedTotalLruFallbackHits() noexcept;
  uint64_t expectedQuicRoutingWithCh() noexcept;
  uint64_t expectedQuicRoutingWithCid() noexcept;
  uint64_t expectedQuicCidV1Counts() noexcept;
  uint64_t expectedQuicCidV2Counts() noexcept;
  uint64_t expectedQuicCidDropsReal0Counts() noexcept;
  uint64_t expectedQuicCidDropsNoRealCounts() noexcept;
  uint64_t expectedTcpServerIdRoutingCounts() noexcept;
  uint64_t expectedTcpServerIdRoutingFallbackCounts() noexcept;
  uint64_t expectedTotalFailedBpfCalls() noexcept;
  uint64_t expectedTotalAddressValidations() noexcept;
  // optional counters
  uint64_t expectedIcmpV4Counts() noexcept;
  uint64_t expectedIcmpV6Counts() noexcept;
  uint64_t expectedSrcRoutingPktsLocal() noexcept;
  uint64_t expectedSrcRoutingPktsRemote() noexcept;
  uint64_t expectedInlineDecapPkts() noexcept;

  // helper method to lookup the expected counter value
  uint64_t _lookup_counter(KatranTestCounters counter) noexcept;

  std::unordered_map<KatranTestCounters, uint64_t> expectedCounters;
  // counters for vip-key -> (per-vip-packets, per-vip-bytes)
  std::
      unordered_map<katran::VipKey, std::pair<uint64_t, uint64_t>, VipKeyHasher>
          perVipCounters;
};

void addReals(
    katran::KatranLb& lb,
    const katran::VipKey& vip,
    const std::vector<std::string>& reals);

void addQuicMappings(katran::KatranLb& lb);

void prepareLbData(katran::KatranLb& lb);

void prepareOptionalLbData(katran::KatranLb& lb);

void preparePerfTestingLbData(katran::KatranLb& lb);
} // namespace testing
} // namespace katran
