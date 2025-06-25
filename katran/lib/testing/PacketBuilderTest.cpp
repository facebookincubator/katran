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

#include "katran/lib/testing/PacketBuilder.h"

#include <gtest/gtest.h>

using namespace katran::testing;

TEST(PacketBuilderTest, BasicUdpPacket) {
  auto packet = PacketBuilder::newPacket()
                    .Eth("01:00:00:00:00:00", "02:00:00:00:00:00")
                    .IPv4("192.168.1.1", "10.200.1.1")
                    .UDP(31337, 80)
                    .payload("katran test pkt")
                    .build();

  EXPECT_EQ(
      packet.base64Packet,
      "AgAAAAAAAQAAAAAACABFAAArAAEAAEARrU/AqAEBCsgBAXppAFAAF5fea2F0cmFuIHRlc3QgcGt0");
  EXPECT_EQ(
      packet.scapyCommand,
      "Ether(src='01:00:00:00:00:00', dst='02:00:00:00:00:00')/IP(src='192.168.1.1', dst='10.200.1.1')/UDP(sport=31337, dport=80)/'katran test pkt'");
}

TEST(PacketBuilderTest, TcpV4Packet) {
  auto packet = PacketBuilder::newPacket()
                    .Eth("0x1", "0x2")
                    .IPv4("192.168.1.1", "10.200.1.1")
                    .TCP(31337, 80, 0, 0, 8192, 0x10) // ACK flag
                    .payload("katran test pkt")
                    .build();

  EXPECT_EQ(
      packet.base64Packet,
      "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGrU7AqAEBCsgBAXppAFAAAAAAAAAAAFAQIAAn5AAAa2F0cmFuIHRlc3QgcGt0");
  EXPECT_EQ(
      packet.scapyCommand,
      "Ether(src='01:00:00:00:00:00', dst='02:00:00:00:00:00')/IP(src='192.168.1.1', dst='10.200.1.1')/TCP(sport=31337, dport=80, flags='A')/'katran test pkt'");
}

TEST(PacketBuilderTest, TcpV4PacketWithToS) {
  auto packet = PacketBuilder::newPacket()
                    .Eth("0x1", "0x2")
                    .IPv4("192.168.1.1", "10.200.1.1", 64, 0x8c) // ToS = 0x8c
                    .TCP(31337, 80, 0, 0, 8192, 0x10) // ACK flag
                    .payload("katran test pkt")
                    .build();

  EXPECT_EQ(
      packet.base64Packet,
      "AgAAAAAAAQAAAAAACABFjAA3AAEAAEAGrMLAqAEBCsgBAXppAFAAAAAAAAAAAFAQIAAn5AAAa2F0cmFuIHRlc3QgcGt0");
  EXPECT_EQ(
      packet.scapyCommand,
      "Ether(src='01:00:00:00:00:00', dst='02:00:00:00:00:00')/IP(src='192.168.1.1', dst='10.200.1.1', tos=140)/TCP(sport=31337, dport=80, flags='A')/'katran test pkt'");
}

TEST(PacketBuilderTest, TcpV4PacketAnyDstPort) {
  auto packet = PacketBuilder::newPacket()
                    .Eth("0x1", "0x2")
                    .IPv4("192.168.1.1", "10.200.1.2")
                    .TCP(31337, 42, 0, 0, 8192, 0x10) // dport=42, ACK flag
                    .payload("katran test pkt")
                    .build();

  EXPECT_EQ(
      packet.base64Packet,
      "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGrU3AqAEBCsgBAnppACoAAAAAAAAAAFAQIAAoCQAAa2F0cmFuIHRlc3QgcGt0");
  EXPECT_EQ(
      packet.scapyCommand,
      "Ether(src='01:00:00:00:00:00', dst='02:00:00:00:00:00')/IP(src='192.168.1.1', dst='10.200.1.2')/TCP(sport=31337, dport=42, flags='A')/'katran test pkt'");
}

TEST(PacketBuilderTest, TcpV4ToV6Real) {
  auto packet = PacketBuilder::newPacket()
                    .Eth("0x1", "0x2")
                    .IPv4("192.168.1.1", "10.200.1.3") // dst="10.200.1.3"
                    .TCP(31337, 80, 0, 0, 8192, 0x10) // ACK flag
                    .payload("katran test pkt")
                    .build();

  EXPECT_EQ(
      packet.base64Packet,
      "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGrUzAqAEBCsgBA3ppAFAAAAAAAAAAAFAQIAAn4gAAa2F0cmFuIHRlc3QgcGt0");
  EXPECT_EQ(
      packet.scapyCommand,
      "Ether(src='01:00:00:00:00:00', dst='02:00:00:00:00:00')/IP(src='192.168.1.1', dst='10.200.1.3')/TCP(sport=31337, dport=80, flags='A')/'katran test pkt'");
}
