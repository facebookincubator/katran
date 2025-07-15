// clang-format off

/* Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved
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
#include <vector>
#include "katran/lib/testing/tools/PacketAttributes.h"
#include "katran/lib/testing/tools/PacketBuilder.h"

/**
 * Test fixtures for XPop (Cross-Pop) decapsulation functionality.
 * 
 * Each test case is generated using PacketBuilder and contains:
 * - inputPacketBuilder: PacketBuilder object for input packet
 * - expectedOutputPacketBuilder: PacketBuilder object for expected output packet
 * - description: Test case description
 * - expectedReturnValue: Expected BPF program return code (XDP_TX, XDP_DROP, XDP_PASS)
 *
 * PacketBuilder Usage:
 *   PacketBuilder::newPacket()
 *       .Eth("01:00:00:00:00:00", "02:00:00:00:00:00")
 *       .IPv4("192.168.1.1", "10.200.1.1")
 *       .UDP(31337, 80)
 *       .payload("katran test pkt")
 *
 * For GUE encapsulation:
 *   PacketBuilder::newPacket()
 *       .Eth("01:00:00:00:00:00", "02:00:00:00:00:00")
 *       .IPv6("100::64", "fc00:1404::1")     // outer IPv6
 *       .UDP(31337, 9886)                    // outer UDP (GUE)
 *       .IPv4("192.168.1.1", "10.200.1.1")  // inner IPv4
 *       .UDP(31337, 80)                      // inner UDP
 *       .payload("katran test pkt")
 *
 * Requirements:
 * - INLINE_DECAP_GUE feature must be enabled for all tests
 * - Tests cover IPv4/IPv6 decap scenarios with various backend types
 * - Includes TTL/hop limit expiration and address mismatch cases
 */

namespace katran {
namespace testing {

const std::vector<::katran::PacketAttributes> xPopDecapTestFixtures = {
  //1
  {
    .description = "Xpop decap and re-encap: IPv6 decap VIP, IPv4 dst VIP with IPv4 backends.",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv6("100::64", "fc00:1404::1", 64)
        .UDP(31337, 9886)
        .IPv4("192.168.1.3", "10.200.1.1")
        .UDP(31337, 80)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv4("10.0.13.37", "10.0.0.2", 64, 0, 0)
        .UDP(26745, 9886)
        .IPv4("192.168.1.3", "10.200.1.1", 63, 0, 1)  // Inner IPv4: TTL=63, ID=1
        .UDP(31337, 80)                                 // Inner UDP
        .payload("katran test pkt")
  },
  //2
  {
    .description = "Xpop decap and re-encap: IPv6 decap VIP, IPv4 dst VIP with IPv6 backends.",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv6("100::64", "fc00:1404::1", 64)
        .UDP(31337, 9886)
        .IPv4("192.168.1.3", "10.200.1.2")
        .UDP(31337, 80)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv6("fc00:2307::1337", "fc00::3", 64)
        .UDP(31594, 9886)
        .IPv4("192.168.1.3", "10.200.1.2", 63, 0, 1)  // Inner IPv4: TTL=63, ID=1
        .UDP(31337, 80)                                 // Inner UDP
        .payload("katran test pkt")
  },
  //3
  {
    .description = "Xpop decap and re-encap: IPv6 decap VIP, IPv6 dst VIP with TCP payload.",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv6("100::64", "fc00:1404::1", 64)
        .UDP(31337, 9886)
        .IPv6("fc00:2307:1::2", "fc00:1::1")
        .TCP(31337, 80, 0, 0, 8192, 0x10)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv6("fc00:2307::1337", "fc00::1", 64)
        .UDP(31337, 9886)
        .IPv6("fc00:2307:1::2", "fc00:1::1", 63)  // Inner IPv6: hlim=63
        .TCP(31337, 80, 0, 0, 8192, 0x10)         // Inner TCP
        .payload("katran test pkt")
  },
  //4
  {
    .description = "Xpop decap and drop: IPv6 decap VIP, IPv4 dst VIP with TTL expired.",
    .expectedReturnValue = "XDP_DROP",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv6("100::64", "fc00:1404::1", 64)
        .UDP(31337, 9886)
        .IPv4("192.168.1.3", "10.200.1.1", 1)
        .UDP(31337, 80)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("01:00:00:00:00:00", "02:00:00:00:00:00")
        .IPv4("192.168.1.3", "10.200.1.1", 0, 0, 1)  // TTL=0 (expired), TOS=0, ID=1
        .UDP(31337, 80)
        .payload("katran test pkt")
  },
  //5
  {
    .description = "Xpop decap and drop: IPv6 decap VIP, IPv6 dst VIP with hop limit expired.",
    .expectedReturnValue = "XDP_DROP",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv6("100::64", "fc00:1404::1", 64)
        .UDP(31337, 9886)
        .IPv6("fc00:2307:1::2", "fc00:1::1", 1)
        .TCP(31337, 80, 0, 0, 8192, 0x10)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("01:00:00:00:00:00", "02:00:00:00:00:00")
        .IPv6("fc00:2307:1::2", "fc00:1::1", 0)  // hlim=0 (hop limit expired)
        .TCP(31337, 80, 0, 0, 8192, 0x10)  // ACK flag
        .payload("katran test pkt")
  },
  //6
  {
    .description = "Gue encap and pass: strict inline decap address match with IPv6 dst VIP.",
    .expectedReturnValue = "XDP_PASS",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv6("100::64", "fc00:2307::1337", 64)
        .UDP(31337, 9886)
        .IPv6("fc00:2307:1::2", "fc00:1::1")
        .TCP(31337, 80, 0, 0, 8192, 0x10)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("01:00:00:00:00:00", "02:00:00:00:00:00")
        .IPv6("fc00:2307:1::2", "fc00:1::1", 63)  // hlim=63
        .TCP(31337, 80, 0, 0, 8192, 0x10)  // ACK flag
        .payload("katran test pkt")
  },
  //7
  {
    .description = "Gue encap and pass: strict inline decap with address mismatch, IPv6 dst VIP, passed as-is to kernel.",
    .expectedReturnValue = "XDP_PASS",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv6("100::64", "fc00::1", 64)
        .UDP(31337, 9886)
        .IPv6("fc00:2307:1::2", "fc00:1::1")
        .TCP(31337, 80, 0, 0, 8192, 0x10)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("01:00:00:00:00:00", "02:00:00:00:00:00")
        .IPv6("100::64", "fc00::1", 64)
        .UDP(31337, 9886)
        .IPv6("fc00:2307:1::2", "fc00:1::1", 64)  // Inner IPv6: hlim=64
        .TCP(31337, 80, 0, 0, 8192, 0x10)         // Inner TCP
        .payload("katran test pkt")
  }
};

} // namespace testing
} // namespace katran
