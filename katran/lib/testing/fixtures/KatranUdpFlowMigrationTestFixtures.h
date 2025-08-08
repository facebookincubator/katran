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

namespace katran {
namespace testing {
/**
 * Test fixtures for UDP Flow Migration functionality.
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
 * For UDP Flow Migration:
 *   PacketBuilder::newPacket()
 *       .Eth("0x1", "0x2")
 *       .IPv4("10.0.0.1", "10.200.1.1")
 *       .UDP(31337, 80)
 *       .payload("katran test pkt")
 */
const std::vector<::katran::PacketAttributes> udpFlowMigrationTestFirstFixtures = {
  // 1. UDP packet to a VIP with flow migration enabled
  {
    .description = "UDP packet to a VIP with flow migration enabled",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv4("10.0.0.1", "10.200.1.1")
        .UDP(31337, 80)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv4("10.0.13.37", "10.0.0.2", 64, 0, 0) // Set ID to 0
        .UDP(27003, 9886)
        .IPv4("10.0.0.1", "10.200.1.1")
        .UDP(31337, 80)
        .payload("katran test pkt")
  },

  // 2. UDP packet to a udp stable routing VIP with flow migration enabled
  {
    .description = "UDP packet to a udp stable routing VIP with flow migration enabled",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv4("10.0.0.1", "10.200.1.2")
        .UDP(31337, 80)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv4("10.0.13.37", "10.0.0.2", 64, 0, 0) // Set ID to 0
        .UDP(27003, 9886)
        .IPv4("10.0.0.1", "10.200.1.2")
        .UDP(31337, 80)
        .payload("katran test pkt")
  },

  // 3. UDP packet to a UDP VIP no flow migration
  {
    .description = "UDP packet to a UDP VIP no flow migration",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv4("10.0.0.1", "10.200.1.3")
        .UDP(31337, 80)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv4("10.0.13.37", "10.0.0.2", 64, 0, 0)
        .UDP(27003, 9886)
        .IPv4("10.0.0.1", "10.200.1.3")
        .UDP(31337, 80)
        .payload("katran test pkt")
  },

  // 4. TCP packet to a TCP vip
  {
    .description = "TCP packet to a TCP vip",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv4("10.0.0.1", "10.200.1.4")
        .TCP(31337, 80)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv4("10.0.13.37", "10.0.0.2",  64, 0, 0)
        .UDP(27003, 9886)
        .IPv4("10.0.0.1", "10.200.1.4")
        .TCP(31337, 80)
        .payload("katran test pkt")
  },

};

const std::vector<::katran::PacketAttributes> udpFlowMigrationTestSecondFixtures = {
  // 1. UDP packet to a VIP with flow migration enabled
  {
    .description = "UDP packet to a VIP with flow migration enabled - new backend as it was redirected",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv4("10.0.0.1", "10.200.1.1")
        .UDP(31337, 80)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv6("fc00:2307::1337", "fc00::2", 64, 0, 0)
        .UDP(31336, 9886)
        .IPv4("10.0.0.1", "10.200.1.1", 64, 0, 1)
        .UDP(31337, 80)
        .payload("katran test pkt")
  },

  // 2. UDP packet to a udp stable routing VIP with flow migration enabled
  {
    .description = "UDP packet to a udp stable routing VIP with flow migration enabled - new backend as it was redirected",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv4("10.0.0.1", "10.200.1.2")
        .UDP(31337, 80)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv6("fc00:2307::1337", "fc00::2",  64, 0, 0)
        .UDP(31336, 9886)
        .IPv4("10.0.0.1", "10.200.1.2")
        .UDP(31337, 80)
        .payload("katran test pkt")
  },

  // 3. UDP packet to a UDP VIP no flow migration
  {
    .description = "UDP packet to a UDP VIP no flow migration",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv4("10.0.0.1", "10.200.1.3")
        .UDP(31337, 80)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv4("10.0.13.37", "10.0.0.2",  64, 0, 0)
        .UDP(27003, 9886)
        .IPv4("10.0.0.1", "10.200.1.3")
        .UDP(31337, 80)
        .payload("katran test pkt")
  },

  // 4. TCP packet to a TCP vip
  {
    .description = "TCP packet to a TCP vip",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv4("10.0.0.1", "10.200.1.4")
        .TCP(31337, 80)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv4("10.0.13.37", "10.0.0.2",  64, 0, 0)
        .UDP(27003, 9886)
        .IPv4("10.0.0.1", "10.200.1.4")
        .TCP(31337, 80)
        .payload("katran test pkt")
  },

};

}
}
