// clang-format off

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
#include <vector>
#include "katran/lib/testing/tools/PacketAttributes.h"
#include "katran/lib/testing/tools/PacketBuilder.h"

extern "C" {
#include <netinet/tcp.h>
}

/**
 * Test fixtures for VIP decapsulation statistics functionality.
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
 *       .IPv6("100::64", "fc00:1::1")        // outer IPv6 - to VIP
 *       .UDP(31337, 9886)                    // outer UDP (GUE)
 *       .IPv4("192.168.1.1", "10.200.1.1")  // inner IPv4 - client to VIP
 *       .UDP(31337, 80)                      // inner UDP
 *       .payload("katran test pkt")
 *
 * Requirements:
 * - INLINE_DECAP_GUE feature must be enabled for decap tests
 * - Tests cover scenarios where GUE packets hit configured VIPs
 * - VIP decap stats counters should be incremented for successful decaps
 */

namespace katran {
namespace testing {

const std::vector<PacketAttributes> GUEDecapTestFixtures = {
  //1
  {
    .description = "GUE IPv6-in-IPv6 decap for IPv6 VIP fc00:1::1 port 80",
    .expectedReturnValue = "XDP_PASS",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv6("100::64", "fc00:2307::1337")    // outer IPv6 - destination is Katran source for inline decap
        .UDP(31337, 9886)                      // GUE encapsulation port 9886
        .IPv6("fc00:2307:1::2", "fc00:1::1")   // inner IPv6 - from client to VIP
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv6("fc00:2307:1::2", "fc00:1::1", 63)  // inner packet after decap, hop limit decremented
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)       // inner TCP
        .payload("katran test pkt")
  },
  //2
  {
    .description = "GUE IPv4-in-IPv6 decap for IPv4 VIP 10.200.1.1 port 80",
    .expectedReturnValue = "XDP_PASS",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv6("100::64", "fc00:2307::1337")      // outer IPv6 - destination is Katran source for inline decap
        .UDP(31337, 9886)                        // GUE encapsulation port 9886
        .IPv4("192.168.1.3", "10.200.1.1")      // inner IPv4 - from client to VIP
        .UDP(31337, 80)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv4("192.168.1.3", "10.200.1.1", 63, 0, 1)    // inner packet after decap, TTL decremented, ID=1
        .UDP(31337, 80)                                   // inner UDP
        .payload("katran test pkt")
  },
  //3
  {
    .description = "Regular IPv6 VIP traffic (not decap) to fc00:1::1",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv6("100::64", "fc00:1::1")
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv6("fc00:2307::1337", "fc00::2")   // encapsulated to IPv6 backend
        .UDP(31337, 9886)
        .IPv6("100::64", "fc00:1::1")
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)
        .payload("katran test pkt")
  }
};

} // namespace testing
} // namespace katran
