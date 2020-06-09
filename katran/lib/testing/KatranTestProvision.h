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

// packet and bytes stats for reals
extern const std::vector<::katran::lb_stats> kRealStats;

constexpr uint16_t kVipPort = 80;
constexpr uint8_t kUdp = 17;
constexpr uint8_t kTcp = 6;
constexpr uint32_t kDefaultWeight = 1;
constexpr uint32_t kDportHash = 8;
constexpr uint32_t kQuicVip = 4;
constexpr uint32_t kSrcRouting = 16;

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
