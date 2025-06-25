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

#include <string>
#include "katran/lib/testing/PacketBuilder.h"

namespace katran {
namespace testing {

/**
 * Generator functions for test input packets using PacketBuilder.
 * These functions generate packets with various structures for testing
 * different networking scenarios.
 */

inline PacketBuilder::PacketResult generateGueIPv4UdpPacket() {
  return PacketBuilder::newPacket()
      .Eth("0x1", "0x2")
      .IPv6("100::64", "fc00:1404::1", 64)
      .UDP(31337, 9886)
      .IPv4("192.168.1.3", "10.200.1.1")
      .UDP(31337, 80)
      .payload("katran test pkt")
      .build();
}

inline PacketBuilder::PacketResult generateGueIPv4UdpPacketAltDst() {
  return PacketBuilder::newPacket()
      .Eth("0x1", "0x2")
      .IPv6("100::64", "fc00:1404::1", 64)
      .UDP(31337, 9886)
      .IPv4("192.168.1.3", "10.200.1.2")
      .UDP(31337, 80)
      .payload("katran test pkt")
      .build();
}

inline PacketBuilder::PacketResult generateGueIPv6TcpPacket() {
  return PacketBuilder::newPacket()
      .Eth("0x1", "0x2")
      .IPv6("100::64", "fc00:1404::1", 64)
      .UDP(31337, 9886)
      .IPv6("fc00:2307:1::2", "fc00:1::1")
      .TCP(31337, 80, 0, 0, 8192, 0x10)
      .payload("katran test pkt")
      .build();
}

inline PacketBuilder::PacketResult generateGueIPv4UdpTtlExpiredPacket() {
  return PacketBuilder::newPacket()
      .Eth("0x1", "0x2")
      .IPv6("100::64", "fc00:1404::1", 64)
      .UDP(31337, 9886)
      .IPv4("192.168.1.3", "10.200.1.1", 1) // TTL=1 for expired packet
      .UDP(31337, 80)
      .payload("katran test pkt")
      .build();
}

inline PacketBuilder::PacketResult generateGueIPv6TcpHlimExpiredPacket() {
  return PacketBuilder::newPacket()
      .Eth("0x1", "0x2")
      .IPv6("100::64", "fc00:1404::1", 64)
      .UDP(31337, 9886)
      .IPv6("fc00:2307:1::2", "fc00:1::1", 1)
      .TCP(31337, 80, 0, 0, 8192, 0x10)
      .payload("katran test pkt")
      .build();
}

inline PacketBuilder::PacketResult generateGueIPv6TcpStrictMatchPacket() {
  return PacketBuilder::newPacket()
      .Eth("0x1", "0x2")
      .IPv6("100::64", "fc00:2307::1337", 64)
      .UDP(31337, 9886)
      .IPv6("fc00:2307:1::2", "fc00:1::1")
      .TCP(31337, 80, 0, 0, 8192, 0x10)
      .payload("katran test pkt")
      .build();
}

inline PacketBuilder::PacketResult generateGueIPv6TcpMismatchPacket() {
  return PacketBuilder::newPacket()
      .Eth("0x1", "0x2")
      .IPv6("100::64", "fc00::1", 64)
      .UDP(31337, 9886)
      .IPv6("fc00:2307:1::2", "fc00:1::1")
      .TCP(31337, 80, 0, 0, 8192, 0x10)
      .payload("katran test pkt")
      .build();
}

} // namespace testing
} // namespace katran
