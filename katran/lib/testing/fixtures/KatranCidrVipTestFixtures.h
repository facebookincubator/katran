// clang-format off

/* Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved.
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
#include "katran/lib/testing/tools/PacketAttributes.h"
#include "katran/lib/testing/tools/PacketBuilder.h"

namespace katran {
namespace testing {
/**
 * Test fixtures for CIDR_VIP feature.
 *
 * This feature enables prefix-based VIP matching using an LPM trie. When a
 * packet's destination IPv6 address does not match any exact VIP in vip_map,
 * the datapath falls back to vip_lpm_map for prefix-based matching.
 *
 * Setup: A /96 CIDR VIP is added at fc00:1::/96 with reals fc00::1 and fc00::2.
 * Packets to any address in fc00:1::0/96 (e.g., fc00:1::100, fc00:1::200)
 * should match the CIDR VIP and be load-balanced to a real.
 *
 * Test cases cover:
 * - IPv6 TCP packet matching CIDR VIP prefix (different IPs in /96 range)
 * - IPv6 UDP packet matching CIDR VIP prefix
 * - IPv6 packet NOT matching any prefix (XDP_PASS)
 * - IPv4 packet should not match CIDR VIP (IPv6 only)
 *
 * Note: These fixtures use GUE encapsulation.
 */
const std::vector<::katran::PacketAttributes> cidrVipTestFixtures = {
    // 1
    // ipv6 TCP: dst fc00:1::100 matches CIDR VIP fc00:1::/96 (port=0 means
    // all ports). Routes to real fc00::1 via GUE encap.
    {.description = "ipv6 tcp: CIDR VIP match. CIDR_VIP is required",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv6("fc00:2::1", "fc00:1::100")
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt"),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
         .IPv6("fc00:2307::1337", "fc00::1", 64, 0, 0)
         .UDP(31337, 9886)
         .IPv6("fc00:2::1", "fc00:1::100")
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt")
    },
    // 2
    // ipv6 TCP: dst fc00:1::200 also matches CIDR VIP fc00:1::/96 (port=0
    // means all ports). Different dest IP in same /96, should match same VIP.
    {.description = "ipv6 tcp: CIDR VIP match different IP in range. CIDR_VIP is required",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv6("fc00:2::1", "fc00:1::200")
         .TCP(31337, 443, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt"),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
         .IPv6("fc00:2307::1337", "fc00::1", 64, 0, 0)
         .UDP(31337, 9886)
         .IPv6("fc00:2::1", "fc00:1::200")
         .TCP(31337, 443, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt")
    },
    // 3
    // ipv6 TCP: dst fc00:1::400 with a different port (8080) matches
    // CIDR VIP fc00:1::/96 (port=0 means all ports).
    // Packet misses vip_map (exact port), misses vip_map (port=0),
    // then hits LPM trie.
    {.description = "ipv6 tcp: CIDR VIP match on different port. CIDR_VIP is required",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv6("fc00:2::1", "fc00:1::400")
         .TCP(31337, 8080, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt"),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
         .IPv6("fc00:2307::1337", "fc00::1", 64, 0, 0)
         .UDP(31337, 9886)
         .IPv6("fc00:2::1", "fc00:1::400")
         .TCP(31337, 8080, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt")
    },
    // 4
    // ipv6: dst fc00:3::1 does NOT match CIDR VIP fc00:1::/96 (port=0 means
    // all ports, but prefix doesn't match). Should be passed to kernel stack.
    {.description = "ipv6: CIDR VIP miss. CIDR_VIP is required",
     .expectedReturnValue = "XDP_PASS",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv6("fc00:2::1", "fc00:3::1")
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt"),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv6("fc00:2::1", "fc00:3::1")
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt")
    },
};

} // namespace testing
} // namespace katran
