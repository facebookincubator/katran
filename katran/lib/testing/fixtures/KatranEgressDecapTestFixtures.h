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
 * Test fixtures for egress decapsulation (XDP_TX after GUE decap).
 *
 * Unlike xpop decap which recirculates the inner packet through Katran,
 * egress decap strips the GUE header, swaps MACs, and returns XDP_TX
 * directly. Used for DSR egress from cloud backends (EoPC).
 *
 * Input packets: GUE-encapsulated to the egress decap VIP (fc00:1405::1).
 * Expected output: inner packet with MACs swapped (dst=src, src=dst of input).
 */

namespace katran {
namespace testing {

const std::vector<::katran::PacketAttributes> egressDecapTestFixtures = {
  //1: Egress decap IPv4 inner packet — XDP_TX with MAC swap
  {
    .description = "Egress decap: GUE IPv6->IPv4 inner, XDP_TX with MAC swap.",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv6("100::64", "fc00:1405::1", 64)
        .UDP(31337, 9886)
        .IPv4("10.200.1.1", "192.168.1.3", 64)
        .UDP(80, 31337)
        .payload("egress decap test"),
    // After decap: inner packet with MACs swapped (0x2 -> dst, 0x1 -> src)
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "01:00:00:00:00:00")
        .IPv4("10.200.1.1", "192.168.1.3", 63, 0, 1)
        .UDP(80, 31337)
        .payload("egress decap test")
  },
  //2: Egress decap IPv6 inner packet — XDP_TX with MAC swap
  {
    .description = "Egress decap: GUE IPv6->IPv6 inner, XDP_TX with MAC swap.",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv6("100::64", "fc00:1405::1", 64)
        .UDP(31337, 9886)
        .IPv6("fc00:1::1", "fc00:2307:1::2", 64)
        .TCP(80, 31337, 0, 0, 8192, 0x10)
        .payload("egress decap test"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "01:00:00:00:00:00")
        .IPv6("fc00:1::1", "fc00:2307:1::2", 63)
        .TCP(80, 31337, 0, 0, 8192, 0x10)
        .payload("egress decap test")
  },
  //3: Egress decap with TTL expired — XDP_DROP
  {
    .description = "Egress decap: GUE IPv6->IPv4 inner with TTL expired, XDP_DROP.",
    .expectedReturnValue = "XDP_DROP",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv6("100::64", "fc00:1405::1", 64)
        .UDP(31337, 9886)
        .IPv4("10.200.1.1", "192.168.1.3", 1)
        .UDP(80, 31337)
        .payload("egress decap test"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("01:00:00:00:00:00", "02:00:00:00:00:00")
        .IPv4("10.200.1.1", "192.168.1.3", 0, 0, 1)
        .UDP(80, 31337)
        .payload("egress decap test")
  },
};

} // namespace testing
} // namespace katran
