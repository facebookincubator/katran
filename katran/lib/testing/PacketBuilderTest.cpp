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

#include <folly/base64.h>
#include <gtest/gtest.h>

using namespace katran::testing;

class PacketBuilderTest : public ::testing::Test {
 protected:
  // Test fixture for PacketBuilder tests
};

TEST_F(PacketBuilderTest, BasicUdpPacket) {
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

TEST_F(PacketBuilderTest, TcpV4Packet) {
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

TEST_F(PacketBuilderTest, TcpV4PacketWithToS) {
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

TEST_F(PacketBuilderTest, TcpV4PacketAnyDstPort) {
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

TEST_F(PacketBuilderTest, TcpV4ToV6Real) {
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

TEST_F(PacketBuilderTest, StableRoutingPayloadMatchesOriginalFormat) {
  // Test that new builder produces same result as original hardcoded packet
  auto packet = PacketBuilder::newPacket()
                    .Eth("0x1", "0x2")
                    .IPv6("fc00:1::1", "fc00:1::9")
                    .UDP(31337, 80)
                    .stableRoutingPayload({}, "local test pkt")
                    .build();

  // Compare with original base64 from fixtures
  EXPECT_EQ(
      packet.base64Packet,
      "AgAAAAAAAQAAAAAAht1gAAAAAB4RQPwAAAEAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAAJemkAUAAeiztSAAAAAAAAAGxvY2FsIHRlc3QgcGt0");
}
TEST_F(PacketBuilderTest, StableRoutingPayloadEmptyConnectionId) {
  auto packet = PacketBuilder::newPacket()
                    .Eth("0x1", "0x2")
                    .IPv4("192.168.1.1", "10.200.1.1")
                    .UDP(31337, 80)
                    .stableRoutingPayload({}, "test")
                    .build();

  auto binaryPacket = folly::base64Decode(packet.base64Packet);

  // Find the payload section (after UDP header)
  // Ethernet (14) + IPv4 (20) + UDP (8) = 42 bytes before payload
  ASSERT_GE(
      binaryPacket.size(),
      42 + PacketBuilder::STABLE_UDP_HEADER_SIZE +
          4); // 1 (header) + conn-id + 4 ("test")

  const uint8_t* payloadStart =
      reinterpret_cast<const uint8_t*>(binaryPacket.data()) + 42;

  EXPECT_EQ(payloadStart[0], PacketBuilder::STABLE_UDP_TYPE);

  for (size_t i = 1; i <= PacketBuilder::STABLE_UDP_HEADER_SIZE - 1; ++i) {
    EXPECT_EQ(payloadStart[i], 0x00) << "Byte " << i << " should be 0x00";
  }

  EXPECT_EQ(payloadStart[8], 't');
  EXPECT_EQ(payloadStart[9], 'e');
  EXPECT_EQ(payloadStart[10], 's');
  EXPECT_EQ(payloadStart[11], 't');
}

TEST_F(PacketBuilderTest, StableRoutingPayloadShortConnectionId) {
  auto packet = PacketBuilder::newPacket()
                    .Eth("0x1", "0x2")
                    .IPv4("192.168.1.1", "10.200.1.1")
                    .UDP(31337, 80)
                    .stableRoutingPayload({0x01, 0x02, 0x03}, "data")
                    .build();

  auto binaryPacket = folly::base64Decode(packet.base64Packet);

  // Find the payload section (after UDP header)
  ASSERT_GE(
      binaryPacket.size(),
      42 + PacketBuilder::STABLE_UDP_HEADER_SIZE +
          4); // 1 (header) + conn-id + 4 ("data")

  const uint8_t* payloadStart =
      reinterpret_cast<const uint8_t*>(binaryPacket.data()) + 42;

  EXPECT_EQ(payloadStart[0], PacketBuilder::STABLE_UDP_TYPE);

  EXPECT_EQ(payloadStart[1], 0x01);
  EXPECT_EQ(payloadStart[2], 0x02);
  EXPECT_EQ(payloadStart[3], 0x03);
  EXPECT_EQ(payloadStart[4], 0x00);
  EXPECT_EQ(payloadStart[5], 0x00);
  EXPECT_EQ(payloadStart[6], 0x00);
  EXPECT_EQ(payloadStart[7], 0x00);

  EXPECT_EQ(payloadStart[8], 'd');
  EXPECT_EQ(payloadStart[9], 'a');
  EXPECT_EQ(payloadStart[10], 't');
  EXPECT_EQ(payloadStart[11], 'a');
}

TEST_F(PacketBuilderTest, StableRoutingPayloadFullConnectionId) {
  auto packet =
      PacketBuilder::newPacket()
          .Eth("0x1", "0x2")
          .IPv4("192.168.1.1", "10.200.1.1")
          .UDP(31337, 80)
          .stableRoutingPayload({0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}, "x")
          .build();

  auto binaryPacket = folly::base64Decode(packet.base64Packet);

  // Find the payload section (after UDP header)
  ASSERT_GE(
      binaryPacket.size(),
      42 + PacketBuilder::STABLE_UDP_HEADER_SIZE +
          1); // 1 (header) + conn-id + 1 ("x")

  const uint8_t* payloadStart =
      reinterpret_cast<const uint8_t*>(binaryPacket.data()) + 42;

  EXPECT_EQ(payloadStart[0], PacketBuilder::STABLE_UDP_TYPE);

  EXPECT_EQ(payloadStart[1], 0x01);
  EXPECT_EQ(payloadStart[2], 0x02);
  EXPECT_EQ(payloadStart[3], 0x03);
  EXPECT_EQ(payloadStart[4], 0x04);
  EXPECT_EQ(payloadStart[5], 0x05);
  EXPECT_EQ(payloadStart[6], 0x06);
  EXPECT_EQ(payloadStart[7], 0x07);

  EXPECT_EQ(payloadStart[8], 'x');
}

TEST_F(PacketBuilderTest, StableRoutingPayloadEmptyPayload) {
  auto packet = PacketBuilder::newPacket()
                    .Eth("0x1", "0x2")
                    .IPv4("192.168.1.1", "10.200.1.1")
                    .UDP(31337, 80)
                    .stableRoutingPayload({0xAA, 0xBB}, "")
                    .build();

  auto binaryPacket = folly::base64Decode(packet.base64Packet);

  // Find the payload section (after UDP header)
  ASSERT_GE(
      binaryPacket.size(),
      42 + PacketBuilder::STABLE_UDP_HEADER_SIZE); // 1 (header) +
                                                   // conn-id + 0
                                                   // (empty payload)

  const uint8_t* payloadStart =
      reinterpret_cast<const uint8_t*>(binaryPacket.data()) + 42;

  EXPECT_EQ(payloadStart[0], PacketBuilder::STABLE_UDP_TYPE);

  EXPECT_EQ(payloadStart[1], 0xAA);
  EXPECT_EQ(payloadStart[2], 0xBB);
  for (size_t i = 3; i <= PacketBuilder::STABLE_UDP_HEADER_SIZE - 1; ++i) {
    EXPECT_EQ(payloadStart[i], 0x00) << "Byte " << i << " should be 0x00";
  }

  // Verify total payload size is exactly
  // STABLE_UDP_HEADER_SIZE bytes (header + conn-id, no payload)
  EXPECT_EQ(binaryPacket.size(), 42 + PacketBuilder::STABLE_UDP_HEADER_SIZE);
}

TEST_F(PacketBuilderTest, StableRoutingPayloadConnectionIdTooLarge) {
  EXPECT_THROW(
      {
        PacketBuilder::newPacket()
            .Eth("0x1", "0x2")
            .IPv4("192.168.1.1", "10.200.1.1")
            .UDP(31337, 80)
            .stableRoutingPayload(
                {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, "test")
            .build();
      },
      std::invalid_argument);
}

TEST_F(PacketBuilderTest, StableRoutingPayloadBinaryValues) {
  std::vector<uint8_t> binaryPayloadVec = {0x00, 0xFF, 0x7F, 0x80};
  std::string binaryPayload(binaryPayloadVec.begin(), binaryPayloadVec.end());

  auto packet = PacketBuilder::newPacket()
                    .Eth("0x1", "0x2")
                    .IPv4("192.168.1.1", "10.200.1.1")
                    .UDP(31337, 80)
                    .stableRoutingPayload({0xFF}, binaryPayload)
                    .build();

  auto binaryPacket = folly::base64Decode(packet.base64Packet);

  // Find the payload section (after UDP header)
  // Calculate expected size: STABLE_UDP_HEADER_SIZE
  // (conn-id) + payload length
  size_t expectedPayloadSize =
      PacketBuilder::STABLE_UDP_HEADER_SIZE + 4; // 4 bytes of binary data
  ASSERT_GE(binaryPacket.size(), 42 + expectedPayloadSize);

  const uint8_t* payloadStart =
      reinterpret_cast<const uint8_t*>(binaryPacket.data()) + 42;

  EXPECT_EQ(payloadStart[0], PacketBuilder::STABLE_UDP_TYPE);

  EXPECT_EQ(payloadStart[1], 0xFF);
  for (size_t i = 2; i <= PacketBuilder::STABLE_UDP_HEADER_SIZE - 1; ++i) {
    EXPECT_EQ(payloadStart[i], 0x00) << "Byte " << i << " should be 0x00";
  }
  EXPECT_EQ(payloadStart[8], 0x00);
  EXPECT_EQ(payloadStart[9], 0xFF);
  EXPECT_EQ(payloadStart[10], 0x7F);
  EXPECT_EQ(payloadStart[11], 0x80);
}
