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

#include "katran/lib/testing/tools/PacketBuilder.h"

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

  auto binaryPacket = packet.binaryPacket;

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

  auto binaryPacket = packet.binaryPacket;

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

  auto binaryPacket = packet.binaryPacket;

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

  auto binaryPacket = packet.binaryPacket;

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

  auto binaryPacket = packet.binaryPacket;

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

// TPR Option Tests
TEST_F(PacketBuilderTest, TcpWithTPROptionBasic) {
  auto packet = PacketBuilder::newPacket()
                    .Eth("0x1", "0x2")
                    .IPv4("192.168.1.1", "10.200.1.1")
                    .TCP(31337, 80, 0, 0, 8192, 0x10) // ACK flag
                    .withTPR(0x0401) // TPR ID: 1025
                    .withNOP(2)
                    .payload("katran test pkt")
                    .build();
  // Ether(src="0x1",
  // dst="0x2")/IP(src="192.168.1.1",dst="10.200.1.1")/TCP(sport=31337,
  // dport=80, flags="A", options=[(0xb7,'\x01\x04\x00\x00'),('NOP', 0),('NOP',
  // 0)])/"katran test pkt"
  EXPECT_EQ(
      packet.base64Packet,
      "AgAAAAAAAQAAAAAACABFAAA/AAEAAEAGrUbAqAEBCsgBAXppAFAAAAAAAAAAAHAQIABO0AAAtwYBBAAAAQFrYXRyYW4gdGVzdCBwa3Q=");
}

TEST_F(PacketBuilderTest, TcpWithTPROptionSYN) {
  auto packet = PacketBuilder::newPacket()
                    .Eth("0x1", "0x2")
                    .IPv4("192.168.1.1", "10.200.1.1")
                    .TCP(31337, 80, 0, 0, 8192, TH_SYN) // SYN flag
                    .withTPR(0x00000013) // TPR ID from test case 1
                    .withNOP(2)
                    .payload("katran test pkt")
                    .build();
  // Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1",
  // dst="10.200.1.1")/TCP(sport=31337, dport=80, flags="S", options=[(0xb7,
  // '\x13\x00\x00\x00'),('NOP', 0),('NOP', 0)])/"katran test pkt"
  EXPECT_EQ(
      packet.base64Packet,
      "AgAAAAAAAQAAAAAACABFAAA/AAEAAEAGrUbAqAEBCsgBAXppAFAAAAAAAAAAAHACIAA84gAAtwYTAAAAAQFrYXRyYW4gdGVzdCBwa3Q=");
}

TEST_F(PacketBuilderTest, TcpWithTPROptionDifferentPort) {
  auto packet = PacketBuilder::newPacket()
                    .Eth("0x1", "0x2")
                    .IPv4("192.168.1.1", "10.200.1.2")
                    .TCP(31337, 42, 0, 0, 8192, 0x10) // ACK flag, dport=42
                    .withTPR(0x03ff) // TPR ID: 1023
                    .payload("katran test pkt")
                    .build();
  // Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1",
  // dst="10.200.1.2")/TCP(sport=31337, dport=42, flags="A", options=[(0xb7,
  // '\xff\x03\x00\x00')])/"katran test pkt"
  EXPECT_EQ(
      packet.base64Packet,
      "AgAAAAAAAQAAAAAACABFAAA/AAEAAEAGrUXAqAEBCsgBAnppACoAAAAAAAAAAHAQIABR9gAAtwb/AwAAAABrYXRyYW4gdGVzdCBwa3Q=");
}

TEST_F(PacketBuilderTest, IPv6TcpWithTPROption) {
  auto packet = PacketBuilder::newPacket()
                    .Eth("0x1", "0x2")
                    .IPv6("fc00:2::1", "fc00:1::1")
                    .TCP(31337, 80, 0, 0, 8192, 0x10) // ACK flag
                    .withTPR(0x0400) // TPR ID: 1024
                    .payload("katran test pkt")
                    .build();
  // Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1",
  // dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A",
  // options=[(0xB7,'\x00\x04\x00\x00')])/"katran test pkt"
  EXPECT_EQ(
      packet.base64Packet,
      "AgAAAAAAAQAAAAAAht1gAAAAACsGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAcBAgACY9AAC3BgAEAAAAAGthdHJhbiB0ZXN0IHBrdA==");
}

TEST_F(PacketBuilderTest, TcpHeaderLengthWithTPROption) {
  auto packet = PacketBuilder::newPacket()
                    .Eth("0x1", "0x2")
                    .IPv4("192.168.1.1", "10.200.1.1")
                    .TCP(31337, 80, 0, 0, 8192, 0x10)
                    .withTPR(0x0400) // 6 bytes: kind(1) + length(1) + data(4)
                    .build();

  auto binaryPacket = packet.binaryPacket;

  // TCP header starts at offset 34 (Ethernet 14 + IPv4 20)
  const uint8_t* tcpHeader =
      reinterpret_cast<const uint8_t*>(binaryPacket.data()) + 34;

  // Extract data offset field (bits 4-7 of byte 12)
  uint8_t dataOffset = (tcpHeader[12] >> 4) & 0x0F;

  // Should be 7 (28 bytes): base TCP header (20) + TPR option (6) + padding (2)
  // = 28 bytes
  EXPECT_EQ(dataOffset, 7);
}

TEST_F(PacketBuilderTest, TcpHeaderLengthWithMultipleOptions) {
  auto packet = PacketBuilder::newPacket()
                    .Eth("0x1", "0x2")
                    .IPv4("192.168.1.1", "10.200.1.3")
                    .TCP(31337, 80, 0, 0, 8192, 0x10)
                    .withNOP(4) // 4 bytes
                    .withTPR(0x0402) // 6 bytes: TPR ID 1026
                    .payload("katran test pkt")
                    .build();

  auto binaryPacket = packet.binaryPacket;
  const uint8_t* tcpHeader =
      reinterpret_cast<const uint8_t*>(binaryPacket.data()) + 34;
  uint8_t dataOffset = (tcpHeader[12] >> 4) & 0x0F;

  // Should be 8 (32 bytes): base TCP header (20) + NOP (4) + TPR (6) + padding
  // (2) = 32 bytes
  EXPECT_EQ(dataOffset, 8);
}

TEST_F(PacketBuilderTest, TPROptionFormatValidation) {
  // Test that TPR option is formatted correctly in binary
  auto packet = PacketBuilder::newPacket()
                    .Eth("0x1", "0x2")
                    .IPv4("192.168.1.1", "10.200.1.1")
                    .TCP(31337, 80, 0, 0, 8192, 0x10)
                    .withTPR(0x03FF) // TPR ID: 1023
                    .build();

  auto binaryPacket = packet.binaryPacket;
  const uint8_t* tcpOptions =
      reinterpret_cast<const uint8_t*>(binaryPacket.data()) +
      54; // After TCP base header

  // Verify TPR option format: kind(0xb7) + length(0x06) + data(4 bytes in
  // little-endian order)
  EXPECT_EQ(tcpOptions[0], 0xb7); // TPR option kind
  EXPECT_EQ(tcpOptions[1], 0x06); // TPR option length
  EXPECT_EQ(tcpOptions[2], 0xFF); // TPR ID byte 0 (LSB)
  EXPECT_EQ(tcpOptions[3], 0x03); // TPR ID byte 1
  EXPECT_EQ(tcpOptions[4], 0x00); // TPR ID byte 2
  EXPECT_EQ(tcpOptions[5], 0x00); // TPR ID byte 3 (MSB)
}

TEST_F(PacketBuilderTest, NOPOptionFormatValidation) {
  auto packet = PacketBuilder::newPacket()
                    .Eth("0x1", "0x2")
                    .IPv4("192.168.1.1", "10.200.1.1")
                    .TCP(31337, 80, 0, 0, 8192, 0x10)
                    .withNOP(3)
                    .build();

  auto binaryPacket = packet.binaryPacket;
  const uint8_t* tcpOptions =
      reinterpret_cast<const uint8_t*>(binaryPacket.data()) + 54;

  // Verify NOP options
  EXPECT_EQ(tcpOptions[0], 0x01);
  EXPECT_EQ(tcpOptions[1], 0x01);
  EXPECT_EQ(tcpOptions[2], 0x01);
  EXPECT_EQ(tcpOptions[3], 0x00); // Padding
}

TEST_F(PacketBuilderTest, TcpChecksumWithTPROption) {
  auto packet = PacketBuilder::newPacket()
                    .Eth("0x1", "0x2")
                    .IPv4("192.168.1.1", "10.200.1.1")
                    .TCP(31337, 80, 0, 0, 8192, 0x10)
                    .withTPR(0x0401)
                    .payload("test")
                    .build();

  auto binaryPacket = packet.binaryPacket;
  const uint8_t* tcpHeader =
      reinterpret_cast<const uint8_t*>(binaryPacket.data()) + 34;

  // Extract checksum from packet
  uint16_t packetChecksum = (tcpHeader[16] << 8) | tcpHeader[17];

  EXPECT_NE(packetChecksum, 0);

  // Create identical packet without options for comparison
  auto packetNoOptions = PacketBuilder::newPacket()
                             .Eth("0x1", "0x2")
                             .IPv4("192.168.1.1", "10.200.1.1")
                             .TCP(31337, 80, 0, 0, 8192, 0x10)
                             .payload("test")
                             .build();

  auto binaryPacketNoOptions =
      folly::base64Decode(packetNoOptions.base64Packet);
  const uint8_t* tcpHeaderNoOptions =
      reinterpret_cast<const uint8_t*>(binaryPacketNoOptions.data()) + 34;
  uint16_t checksumNoOptions =
      (tcpHeaderNoOptions[16] << 8) | tcpHeaderNoOptions[17];

  // Checksums should be different due to different TCP segment lengths
  EXPECT_NE(packetChecksum, checksumNoOptions);
}

TEST_F(PacketBuilderTest, TPROptionEdgeCases) {
  // Test TPR ID 0
  auto packet1 = PacketBuilder::newPacket()
                     .Eth("0x1", "0x2")
                     .IPv4("192.168.1.1", "10.200.1.1")
                     .TCP(31337, 80, 0, 0, 8192, 0x10)
                     .withTPR(0x0000)
                     .build();

  EXPECT_FALSE(packet1.base64Packet.empty());

  // Test maximum TPR ID
  auto packet2 = PacketBuilder::newPacket()
                     .Eth("0x1", "0x2")
                     .IPv4("192.168.1.1", "10.200.1.1")
                     .TCP(31337, 80, 0, 0, 8192, 0x10)
                     .withTPR(0xFFFFFFFF)
                     .build();

  EXPECT_FALSE(packet2.base64Packet.empty());
}

TEST_F(PacketBuilderTest, InvalidTcpOptionChaining) {
  EXPECT_THROW(
      {
        PacketBuilder::newPacket()
            .Eth("0x1", "0x2")
            .IPv4("192.168.1.1", "10.200.1.1")
            .withTPR(0x0401)
            .build();
      },
      std::logic_error);

  // Test that calling withNOP() without TCP() throws
  EXPECT_THROW(
      {
        PacketBuilder::newPacket()
            .Eth("0x1", "0x2")
            .IPv4("192.168.1.1", "10.200.1.1")
            .withNOP(2)
            .build();
      },
      std::logic_error);
}

TEST_F(PacketBuilderTest, LargeNumberOfNOPs) {
  auto packet = PacketBuilder::newPacket()
                    .Eth("0x1", "0x2")
                    .IPv6("fc00:2::1", "fc00:1::1")
                    .TCP(31337, 80, 0, 0, 8192, 0x10)
                    .withNOP(14) // 14 NOPs like in test case 13
                    .withTPR(0x0400)
                    .payload("katran test pkt")
                    .build();

  auto binaryPacket = packet.binaryPacket;

  EXPECT_FALSE(packet.base64Packet.empty());

  const uint8_t* tcpHeader =
      reinterpret_cast<const uint8_t*>(binaryPacket.data()) +
      54; // After IPv6 + Ethernet
  uint8_t dataOffset = (tcpHeader[12] >> 4) & 0x0F;

  // Should be properly padded: base(20) + NOPs(14) + TPR(6) = 40 bytes = 10
  // words
  EXPECT_EQ(dataOffset, 10);
}

// UDP Flow Invalidation Tests

TEST_F(PacketBuilderTest, UdpFlowInvalidationBasicPacket) {
  auto packet = PacketBuilder::newPacket()
                    .Eth("0x1", "0x2")
                    .IPv4("10.0.0.1", "10.200.1.1")
                    .UDP(31337, 80)
                    .payload("katran test pkt")
                    .build();

  EXPECT_EQ(
      packet.base64Packet,
      "AgAAAAAAAQAAAAAACABFAAArAAEAAEARZPgKAAABCsgBAXppAFAAF0+Ha2F0cmFuIHRlc3QgcGt0");
  EXPECT_EQ(
      packet.scapyCommand,
      "Ether(src='01:00:00:00:00:00', dst='02:00:00:00:00:00')/IP(src='10.0.0.1', dst='10.200.1.1')/UDP(sport=31337, dport=80)/'katran test pkt'");
}

TEST_F(PacketBuilderTest, UdpFlowInvalidationEncapsulatedPacket) {
  auto packet = PacketBuilder::newPacket()
                    .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
                    .IPv4("10.0.13.37", "10.0.0.2", 64, 0, 0) // Set ID to 0
                    .UDP(27003, 9886)
                    .IPv4("10.0.0.1", "10.200.1.1")
                    .UDP(31337, 80)
                    .payload("katran test pkt")
                    .build();

  EXPECT_EQ(
      packet.base64Packet,
      "AADerb6vAgAAAAAACABFAABHAAAAAEARWYAKAA0lCgAAAml7Jp4AM2Q6RQAAKwABAABAEWT4CgAAAQrIAQF6aQBQABdPh2thdHJhbiB0ZXN0IHBrdA==");
  EXPECT_EQ(
      packet.scapyCommand,
      "Ether(src='02:00:00:00:00:00', dst='00:00:de:ad:be:af')/IP(src='10.0.13.37', dst='10.0.0.2')/UDP(sport=27003, dport=9886)/IP(src='10.0.0.1', dst='10.200.1.1')/UDP(sport=31337, dport=80)/'katran test pkt'");
}
