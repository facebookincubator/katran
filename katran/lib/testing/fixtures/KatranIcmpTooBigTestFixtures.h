// @nolint

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
#include "katran/lib/testing/tools/PacketAttributes.h"

namespace katran {
namespace testing {
/**
 * Input packets generated with PacketBuilder API.
 *
 * Format: PacketAttributes with inputPacketBuilder and
 * expectedOutputPacketBuilder
 *
 * To get base64 packet string from PacketBuilder: builder.build().base64Packet
 */
using TestFixture = std::vector<PacketAttributes>;

// Helper to create repeated payload
inline std::string repeatString(const std::string& str, int count) {
  std::string result;
  result.reserve(str.length() * count);
  for (int i = 0; i < count; ++i) {
    result += str;
  }
  return result;
}

const TestFixture icmpTooBigTestFixtures = {
    {.description =
         "ICMPv4 packet too big. ICMP_TOOBIG_GENERATION and 4.17+ kernel is required",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
                               .Eth("0x1", "0x2")
                               .IPv4("192.168.1.1", "10.200.1.1")
                               .UDP(31337, 80)
                               .payload(repeatString("katran test pkt", 100)),
     .expectedOutputPacketBuilder =
         katran::testing::PacketBuilder::newPacket()
             .Eth("02:00:00:00:00:00", "01:00:00:00:00:00")
             .IPv4("10.200.1.1", "192.168.1.1", 64, 0, 0)
             .ICMPFragNeeded(
                 1500,
                 {.srcIP = "192.168.1.1",
                  .dstIP = "10.200.1.1",
                  .srcPort = 31337,
                  .dstPort = 80,
                  .payload = repeatString("katran test pkt", 100),
                  .ttl = 64,
                  .tos = 0,
                  .id = 1})},
    {.description =
         "ICMPv6 packet too big. ICMP_TOOBIG_GENERATION and 4.17+ kernel is required",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
                               .Eth("0x1", "0x2")
                               .IPv6("fc00:2::1", "fc00:1::1")
                               .TCP(31337, 80, 0, 0, 8192, TH_ACK)
                               .payload(repeatString("katran test pkt", 100)),
     .expectedOutputPacketBuilder =
         katran::testing::PacketBuilder::newPacket()
             .Eth("02:00:00:00:00:00", "01:00:00:00:00:00")
             .IPv6("fc00:1::1", "fc00:2::1")
             .ICMPv6PacketTooBig(
                 1500,
                 {.srcIP = "fc00:2::1",
                  .dstIP = "fc00:1::1",
                  .srcPort = 31337,
                  .dstPort = 80,
                  .seq = 0,
                  .ackSeq = 0,
                  .window = 8192,
                  .flags = TH_ACK,
                  .payload = repeatString("katran test pkt", 100)})},
};

const TestFixture originGueIcmpTooBigTestFixtures = {
    {.description =
         "ICMPv4 packet too big. ICMP_TOOBIG_GENERATION and 4.17+ kernel is required",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
                               .Eth("0x1", "0x2")
                               .IPv4("192.168.1.1", "10.200.1.1")
                               .UDP(31337, 80)
                               .payload(repeatString("katran test pkt", 100)),
     .expectedOutputPacketBuilder =
         katran::testing::PacketBuilder::newPacket()
             .Eth("02:00:00:00:00:00", "01:00:00:00:00:00")
             .IPv4("10.200.1.1", "192.168.1.1", 64, 0, 1)
             .ICMP(
                 ICMPv4Header::DEST_UNREACH,
                 ICMPv4Header::FRAG_NEEDED,
                 0,
                 1452)
             .IPv4("192.168.1.1", "10.200.1.1", 64, 0, 1)
             .UDP(31337, 80)
             .payload(repeatString("katran test pkt", 4))},
    {.description =
         "ICMPv6 packet too big for Origin GUE. ICMP_TOOBIG_GENERATION and 4.17+ kernel is required",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
                               .Eth("0x1", "0x2")
                               .IPv6("fc00:2::1", "fc00:1::1")
                               .TCP(31337, 80, 0, 0, 8192, TH_ACK)
                               .payload(repeatString("katran test pkt", 100)),
     .expectedOutputPacketBuilder =
         katran::testing::PacketBuilder::newPacket()
             .Eth("02:00:00:00:00:00", "01:00:00:00:00:00")
             .IPv6("fc00:1::1", "fc00:2::1")
             .ICMPv6(ICMPv6Header::PACKET_TOO_BIG, 0, 0, 0)
             .IPv6("fc00:2::1", "fc00:1::1")
             .TCP(31337, 80, 0, 0, 8192, TH_ACK)
             .payload(repeatString("katran test pkt", 13))},
};

} // namespace testing
} // namespace katran
