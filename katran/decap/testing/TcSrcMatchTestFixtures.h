// @nolint

/* Copyright (C) 2019-present, Facebook, Inc.
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
#include <cstring>
#include <string>
#include <utility>
#include <vector>
#include <folly/base64.h>
#include <katran/lib/testing/tools/PacketAttributes.h>
#include <katran/lib/testing/tools/PacketBuilder.h>

namespace katran {
namespace testing {

inline std::vector<PacketAttributes> buildTcSrcMatchFixtures() {
  // shivless packet (9887 gue encapped, ipv6, tcp)
  auto before = PacketBuilder::newPacket()
      .Eth("00:00:00:00:00:01", "00:00:00:00:00:02")
      .IPv6("2001:db8::1", "2001:db8::2")
      .UDP(1234, 9887)
      .IPv6("2001:db8::99", "2001:db8::3")
      .TCP(80, 443)
      .payload("test")
      .build();
  auto after = PacketBuilder::newPacket()
      .Eth("00:00:00:00:00:01", "00:00:00:00:00:02")
      .IPv6("2001:db8::1", "2001:db8::2")
      .UDP(1234, 9887)
      .IPv6("2001:db8::1", "2001:db8::3")
      .TCP(80, 443)
      .payload("test")
      .build();

  // Plain IPv4 — pass through
  auto plainIpv4 = PacketBuilder::newPacket()
      .Eth("00:00:00:00:00:01", "00:00:00:00:00:02")
      .IPv4("10.0.0.1", "10.0.0.2")
      .TCP(80, 443)
      .build();

  // IPv6 TCP (not UDP) — pass through
  auto ipv6Tcp = PacketBuilder::newPacket()
      .Eth("00:00:00:00:00:01", "00:00:00:00:00:02")
      .IPv6("2001:db8::1", "2001:db8::2")
      .TCP(80, 443)
      .build();

  // IPv6 UDP wrong port — pass through
  auto wrongPort = PacketBuilder::newPacket()
      .Eth("00:00:00:00:00:01", "00:00:00:00:00:02")
      .IPv6("2001:db8::1", "2001:db8::2")
      .UDP(1234, 53)
      .payload("dns query")
      .build();

  return {
      {
          .inputPacket = before.base64Packet,
          .description = "GUE IPv6-in-IPv6: rewrite inner src to match outer",
          .expectedReturnValue = "TC_ACT_PIPE",
          .expectedOutputPacket = after.base64Packet,
      },
      {
          .inputPacket = plainIpv4.base64Packet,
          .description = "Plain IPv4: pass through",
          .expectedReturnValue = "TC_ACT_PIPE",
          .expectedOutputPacket = plainIpv4.base64Packet,
      },
      {
          .inputPacket = ipv6Tcp.base64Packet,
          .description = "IPv6 TCP: not UDP, pass through",
          .expectedReturnValue = "TC_ACT_PIPE",
          .expectedOutputPacket = ipv6Tcp.base64Packet,
      },
      {
          .inputPacket = wrongPort.base64Packet,
          .description = "IPv6 UDP port 53: not GUE, pass through",
          .expectedReturnValue = "TC_ACT_PIPE",
          .expectedOutputPacket = wrongPort.base64Packet,
      },
  };
}

} // namespace testing
} // namespace katran
