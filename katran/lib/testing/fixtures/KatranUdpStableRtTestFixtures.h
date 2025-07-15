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
 * Test fixtures for UDP Stable Routing functionality.
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
 *       .IPv6("fc00:1::1", "fc00:1::9")
 *       .UDP(31337, 80)
 *       .payload("local test pkt")
 *
 * For UDP Stable Routing with connection ID:
 *   PacketBuilder::newPacket()
 *       .Eth("0x1", "0x2")
 *       .IPv6("fc00:1::1", "fc00:1::9")
 *       .UDP(31337, 80)
 *       .stableRoutingPayload({0x03, 0x04, 0x03}, "local test pkt")  // conn-id: {0x03, 0x04, 0x03}
 *
 * For UDP Stable Routing with connection ID 0 (default routing):
 *   PacketBuilder::newPacket()
 *       .Eth("0x1", "0x2")
 *       .IPv6("fc00:1::1", "fc00:1::9")
 *       .UDP(31337, 80)
 *       .stableRoutingPayload({}, "local test pkt")  // empty conn-id = all zeros
 *
 * Requirements:
 * - Tests cover UDP stable routing with connection ID tracking
 * - Includes LRU cache hit scenarios and different source combinations
 * - Connection ID is embedded in the UDP payload for routing decisions
 */

namespace katran {
namespace testing {
const std::vector<::katran::PacketAttributes> udpStableRtFixtures = {
  //1
  {
    .description = "Stable Rt packet with conn-id 0 - 1",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv6("fc00:1::1", "fc00:1::9")
        .UDP(31337, 80)
        .stableRoutingPayload({}, "local test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv6("fc00:2307::1337", "fc00::3")
        .UDP(31337, 9886)
        .IPv6("fc00:1::1", "fc00:1::9")
        .UDP(31337, 80)
        .stableRoutingPayload({}, "local test pkt")
  },
  //2
  {
    .description = "Stable Rt packet from same src, with conn-id for fc00::3 real - 2",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv6("fc00:1::1", "fc00:1::9")
        .UDP(31337, 80)
        .stableRoutingPayload({0x03, 0x04, 0x03}, "local test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv6("fc00:2307::1337", "fc00::3")
        .UDP(31337, 9886)
        .IPv6("fc00:1::1", "fc00:1::9")
        .UDP(31337, 80)
        .stableRoutingPayload({0x03, 0x04, 0x03}, "local test pkt")
  },
  //3
  {
    .description = "Stable Rt packet from different src port, with conn-id for fc00::3 real - 3",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv6("fc00:1::1", "fc00:1::9")
        .UDP(31339, 80)
        .stableRoutingPayload({0x03, 0x04, 0x03}, "local test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv6("fc00:2307::1337", "fc00::3")
        .UDP(31339, 9886)
        .IPv6("fc00:1::1", "fc00:1::9")
        .UDP(31339, 80)
        .stableRoutingPayload({0x03, 0x04, 0x03}, "local test pkt")
  },
  //4
  {
    .description = "Stable Rt packet from different src ip, with same conn-id for fc00::3 real - 4",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv6("fc00:1::5", "fc00:1::9")
        .UDP(31339, 80)
        .stableRoutingPayload({0x03, 0x04, 0x03}, "local test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv6("fc00:2307::1337", "fc00::3")
        .UDP(31339, 9886)
        .IPv6("fc00:1::5", "fc00:1::9")
        .UDP(31339, 80)
        .stableRoutingPayload({0x03, 0x04, 0x03}, "local test pkt")
  },
  //5
  {
    .description = "Stable Rt packet with conn-id 0, from same original src ip/port, so LRU hit - 5",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv6("fc00:1::1", "fc00:1::9")
        .UDP(31337, 80)
        .stableRoutingPayload({}, "local test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv6("fc00:2307::1337", "fc00::3")
        .UDP(31337, 9886)
        .IPv6("fc00:1::1", "fc00:1::9")
        .UDP(31337, 80)
        .stableRoutingPayload({}, "local test pkt")
  }
};
}
}
