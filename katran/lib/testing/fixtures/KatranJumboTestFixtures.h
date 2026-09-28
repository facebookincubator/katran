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
 * Packets that exceed the standard origin MAX_PCKT_SIZE of 1466 but fit under
 * the jumbo limit of 4966. On a standard origin flavor these are answered with
 * ICMP too big (see originGueIcmpTooBigTestFixtures), so forwarding them
 * normally is what distinguishes a jumbo build.
 *
 * Source addresses use the RFC 5737 documentation range. The VIP and the real
 * come from the shared KatranTestProvision fixture data, not from here.
 *
 * The outer real and UDP source port in the expected output are derived from
 * the flow hash over the input 5-tuple, so changing any address or port here
 * changes them too; re-run the test and take the values it reports rather than
 * editing them by hand.
 *
 * Frames stay under BpfTester's 4096 byte ceiling, so no XDP multi-buffer
 * support is required to run them.
 */
using TestFixture = std::vector<PacketAttributes>;

// 1500 bytes of payload: 14 + 20 + 8 + 1500 = 1542 byte v4/UDP frame, and
// 14 + 20 + 20 + 1500 = 1554 byte v4/TCP frame. Both exceed 1466.
inline std::string jumboPayload() {
  const std::string chunk = "katran test pkt";
  std::string result;
  result.reserve(chunk.length() * 100);
  for (int i = 0; i < 100; ++i) {
    result += chunk;
  }
  return result;
}

const TestFixture originJumboTestFixtures = {
    {.description =
         "oversized packet to UDP based v4 VIP is forwarded, not ICMP too big",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
                               .Eth("0x1", "0x2")
                               .IPv4("192.0.2.1", "10.200.1.1")
                               .UDP(31337, 80)
                               .payload(jumboPayload()),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
                                        .Eth("02:00:00:00:00:00",
                                             "00:00:de:ad:be:af")
                                        .IPv4("10.0.13.37", "10.0.0.1", 64, 0, 0)
                                        .UDP(27515, 9886)
                                        .IPv4("192.0.2.1", "10.200.1.1")
                                        .UDP(31337, 80)
                                        .payload(jumboPayload())},
    {.description =
         "oversized packet to TCP based v4 VIP is forwarded, not ICMP too big",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
                               .Eth("0x1", "0x2")
                               .IPv4("192.0.2.1", "10.200.1.1")
                               .TCP(31337, 80, 0, 0, 8192, TH_ACK)
                               .payload(jumboPayload()),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
                                        .Eth("02:00:00:00:00:00",
                                             "00:00:de:ad:be:af")
                                        .IPv4("10.0.13.37", "10.0.0.1", 64, 0, 0)
                                        .UDP(27515, 9886)
                                        .IPv4("192.0.2.1", "10.200.1.1")
                                        .TCP(31337, 80, 0, 0, 8192, TH_ACK)
                                        .payload(jumboPayload())},
};

} // namespace testing
} // namespace katran
