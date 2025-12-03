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
 * Test fixtures for LPM_SRC_LOOKUP feature.
 *
 * This feature enables source-based routing by looking up the packet's source
 * IP in an LPM (Longest Prefix Match) trie to determine the destination real
 * server. When enabled (F_SRC_ROUTING flag on VIP), packets are routed based
 * on their source IP prefix match rather than consistent hashing.
 *
 * Test cases cover:
 * - IPv4 source routing with /17 and /24 prefix matches
 * - IPv6 source routing with /32 and /64 prefix matches
 * - LPM cache hits (repeated source IPs)
 * - LPM misses (fallback to consistent hashing)
 *
 * Note: These fixtures use GUE encapsulation with:
 * - Outer IPv6 header with katran source (fc00:2307::1337)
 * - UDP header with computed source port and dport=9886
 * - Inner original packet
 */
const std::vector<::katran::PacketAttributes> lpmSrcLookupTestFixtures = {
    // 1
    // ipv4: lpm src lookup /17 - src 192.168.1.2 matches 192.168.0.0/17 rule
    // Routes to remote destination fc00::2307:1 (IPv6 real)
    {.description = "ipv4: lpm cached flow. LPM_SRC_LOOKUP is required",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv4("192.168.1.2", "10.200.1.1")
         .UDP(31337, 80)
         .payload("katran test pkt"),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
         .IPv6("fc00:2307::1337", "fc00::2307:1", 64, 0, 0)
         .UDP(31595, 9886)
         .IPv4("192.168.1.2", "10.200.1.1")
         .UDP(31337, 80)
         .payload("katran test pkt")
    },
    // 2
    // ipv4: lpm src lookup /17 - src 192.168.1.2 matches 192.168.0.0/17 rule
    // Routes to remote destination fc00::2307:1 (IPv6 real)
    {.description = "ipv4: lpm src lookup /17. LPM_SRC_LOOKUP is required",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv4("192.168.1.2", "10.200.1.1")
         .UDP(31337, 80)
         .payload("katran test pkt"),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
         .IPv6("fc00:2307::1337", "fc00::2307:1", 64, 0, 0)
         .UDP(31595, 9886)
         .IPv4("192.168.1.2", "10.200.1.1")
         .UDP(31337, 80)
         .payload("katran test pkt")
    },
    // 3
    // ipv4: lpm src lookup /24 - src 192.168.100.1 matches 192.168.100.0/24 rule
    // Routes to remote destination fc00::2307:2 (IPv6 real)
    {.description = "ipv4: lpm src lookup /24 . LPM_SRC_LOOKUP is required",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv4("192.168.100.1", "10.200.1.1")
         .UDP(31337, 80)
         .payload("katran test pkt"),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
         .IPv6("fc00:2307::1337", "fc00::2307:2", 64, 0, 0)
         .UDP(7784, 9886)
         .IPv4("192.168.100.1", "10.200.1.1")
         .UDP(31337, 80)
         .payload("katran test pkt")
    },
    // 4
    // ipv4: lpm miss - src 192.168.200.1 does NOT match any LPM rule
    // Falls back to consistent hashing, routes to 10.0.0.3 (IPv4 real)
    // GUE encap with outer IPv4
    {.description = "ipv4: lpm miss. LPM_SRC_LOOKUP is required",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv4("192.168.200.1", "10.200.1.1")
         .UDP(31337, 80)
         .payload("katran test pkt"),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
         .IPv4("10.0.13.37", "10.0.0.3", 64, 0, 0)
         .UDP(41339, 9886)
         .IPv4("192.168.200.1", "10.200.1.1")
         .UDP(31337, 80)
         .payload("katran test pkt")
    },
    // 5
    // ipv6: lpm src lookup /64 - src fc00:2::2 matches fc00:2::/64 rule
    // Routes to remote destination fc00::2307:10 (IPv6 real)
    {.description = "ipv6: lpm src lookup /64. LPM_SRC_LOOKUP is required",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv6("fc00:2::2", "fc00:1::1")
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt"),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
         .IPv6("fc00:2307::1337", "fc00::2307:10", 64, 0, 0)
         .UDP(31337, 9886)
         .IPv6("fc00:2::2", "fc00:1::1")
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt")
    },
    // 6
    // ipv6: lpm src lookup /32 - src fc00:2307::1 matches fc00:2307::/64 rule
    // (which is more specific than /32)
    // Routes to remote destination fc00::2307:4 (IPv6 real)
    {.description = "ipv6: lpm src lookup /32. LPM_SRC_LOOKUP is required",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv6("fc00:2307::1", "fc00:1::1")
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt"),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
         .IPv6("fc00:2307::1337", "fc00::2307:4", 64, 0, 0)
         .UDP(31337, 9886)
         .IPv6("fc00:2307::1", "fc00:1::1")
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt")
    },
    // 7
    // ipv6: lpm miss - src fc00:2308:1::1 does NOT match any LPM rule
    // Falls back to consistent hashing, routes to fc00::1 (IPv6 real)
    {.description = "ipv6: lpm miss. LPM_SRC_LOOKUP is required",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv6("fc00:2308:1::1", "fc00:1::1")
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt"),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
         .IPv6("fc00:2307::1337", "fc00::1", 64, 0, 0)
         .UDP(31337, 9886)
         .IPv6("fc00:2308:1::1", "fc00:1::1")
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt")
    },
    // 8
    // ipv6: lpm cached flow - src fc00:2::1 matches fc00:2::/64 rule
    // Routes to remote destination fc00::2307:10 (IPv6 real)
    // This tests the LRU cache hit path
    {.description = "ipv6: lpm cached flow. LPM_SRC_LOOKUP is required",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv6("fc00:2::1", "fc00:1::1")
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt"),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
         .IPv6("fc00:2307::1337", "fc00::2307:10", 64, 0, 0)
         .UDP(31337, 9886)
         .IPv6("fc00:2::1", "fc00:1::1")
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt")
    },
};

} // namespace testing
} // namespace katran
