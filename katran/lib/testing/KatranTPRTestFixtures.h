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
#include "katran/lib/testing/PacketAttributes.h"
#include "katran/lib/testing/PacketBuilder.h"

/**
 * Test fixtures for TPR functionality.
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
 *       .TCP(31337, 80, 0, 0, 8192, 0x10)  // sport, dport, seq, ack, window, flags
 *       .payload("katran test pkt")
 *
 * For TPR option in TCP header:
 *   TCP options are handled automatically by PacketBuilder based on the test scenario
 *
 * Requirements:
 * - Tests cover IPv4/IPv6 TPR scenarios with various backend types
 * - Includes TPR ID parsing and LRU bypass functionality
 * - Tests both IPIP and GUE encapsulation modes
 */

namespace katran {
namespace testing {
const std::vector<::katran::PacketAttributes> tprTestFixtures = {
  //1
  {
    .description = "V4 VIP (and v4 real), SYN, TPR id ignored",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv4("192.168.1.1", "10.200.1.1")
        .TCP(31337, 80, 0, 0, 8192, TH_SYN)
        .withTPR(0x00000013)
        .withNOP(2)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv4("172.16.104.123", "10.0.0.3", 64, 0, 0)
        .IPv4("192.168.1.1", "10.200.1.1", 64, 0, 1)  // Inner IPv4: TTL=64, ID=1
        .TCP(31337, 80, 0, 0, 8192, TH_SYN)
        .withTPR(0x00000013)
        .withNOP(2)
        .payload("katran test pkt")
  },
  //2
  {
    .description = "V4 VIP (and v4 real), TPR Id: 1025",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv4("192.168.1.1", "10.200.1.1")
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)
        .withTPR(0x0401)  // TPR ID: 1025 (0x0401)
        .withNOP(2)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv4("172.16.104.123", "10.0.0.3", 64, 0, 0)
        .IPv4("192.168.1.1", "10.200.1.1", 64, 0, 1)  // Inner IPv4: TTL=64, ID=1
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)
        .withTPR(0x0401)  // TPR ID: 1025 (0x0401)
        .withNOP(2)
        .payload("katran test pkt")
  },
  //3
  {
    .description = "V4 VIP (and v4 real; any dst ports), TPR Id: 1023",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv4("192.168.1.1", "10.200.1.2")
        .TCP(31337, 42, 0, 0, 8192, TH_ACK)
        .withTPR(0x03ff)  // TPR ID: 1023 (0x03ff)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv4("172.16.104.123", "10.0.0.2", 64, 0, 0)  // Outer IP: ID=0
        .IPv4("192.168.1.1", "10.200.1.2", 64, 0, 1)  // Inner IPv4: TTL=64, ID=1
        .TCP(31337, 42, 0, 0, 8192, TH_ACK)
        .withTPR(0x03ff)  // TPR ID: 1023 (0x03ff)
        .payload("katran test pkt")
  },
  //4
  {
    .description = "V4 VIP (and v6 real), TPR Id: 1024.",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv4("192.168.1.1", "10.200.1.3")
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)
        .withNOP(4)
        .withTPR(0x0400)  // TPR ID: 1024
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv6("100::bac1:101", "fc00::1")
        .IPv4("192.168.1.1", "10.200.1.3", 64, 0, 1)  // Inner IPv4: TTL=64, ID=1
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)
        .withNOP(4)
        .withTPR(0x0400)  // TPR ID: 1024
        .payload("katran test pkt")
  },
  //5
  {
    .description = "V6 VIP (and v6 real), TPR Id: 1024",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv6("fc00:2::1", "fc00:1::1")
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)
        .withTPR(0x0400)  // TPR ID: 1024 (0x0400)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv6("100::7a69:1", "fc00::1")
        .IPv6("fc00:2::1", "fc00:1::1", 64)  // Inner IPv6: hlim=64
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)
        .withTPR(0x0400)  // TPR ID: 1024 (0x0400)
        .payload("katran test pkt")
  },
  //6
  {
    .description = "V4 VIP, no TPR, LRU hit",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv4("192.168.1.1", "10.200.1.1")
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv4("172.16.104.123", "10.0.0.3", 64, 0, 0)
        .IPv4("192.168.1.1", "10.200.1.1", 64, 0, 1)  // Inner IPv4: TTL=64, ID=1
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)
        .payload("katran test pkt")
  },
  //7
  {
    .description = "V4 VIP, TPR Id: 1025, bypasses LRU",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv4("192.168.1.1", "10.200.1.1")
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)
        .withTPR(0x0401)  // TPR ID: 1025
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv4("172.16.104.123", "10.0.0.3", 64, 0, 0)
        .IPv4("192.168.1.1", "10.200.1.1", 64, 0, 1)  // Inner IPv4: TTL=64, ID=1
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)
        .withTPR(0x0401)
        .payload("katran test pkt")
  },
  //8
  {
    .description = "V6 VIP, V6 real, no TPR Id, LRU hit",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv6("fc00:2::1", "fc00:1::1")
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)  // ACK flag
        .withTimestamp(1, 3)
        .withNOP(2)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv6("100::7a69:1", "fc00::1")
        .IPv6("fc00:2::1", "fc00:1::1", 64)  // Inner IPv6: hlim=64
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)    // Inner TCP: ACK flag
        .withTimestamp(1, 3)
        .withNOP(2)
        .payload("katran test pkt")
  },
  //9
  {
    .description = "V6 VIP, V6 real, TPR Id 0, LRU hit",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv6("fc00:2::1", "fc00:1::1")
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)  // ACK flag
        .withTPR(0x0000)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv6("100::7a69:1", "fc00::1")
        .IPv6("fc00:2::1", "fc00:1::1", 64)  // Inner IPv6: hlim=64
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)    // Inner TCP: ACK flag
        .withTPR(0x0000)
        .payload("katran test pkt")
  },
  //10
  {
    .description = "V6 VIP, V6 real, TPR Id: 1024, bad hdr len, LRU hit",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv6("fc00:2::1", "fc00:1::1")
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)  // ACK flag
        .withCustomOption(0xb7, std::vector<uint8_t>{0x04, 0x00})  // Malformed TPR option
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv6("100::7a69:1", "fc00::1")
        .IPv6("fc00:2::1", "fc00:1::1", 64)  // Inner IPv6: hlim=64
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)    // Inner TCP: ACK flag
        .withCustomOption(0xb7, std::vector<uint8_t>{0x04, 0x00})  // Malformed TPR option
        .payload("katran test pkt")
  },
  //11
  {
    .description = "V6 VIP, V6 real, TPR Id: 1024, bypasses LRU",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv6("fc00:2::1", "fc00:1::1")
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)  // ACK flag
        .withTPR(0x0400)  // TPR ID: 1024
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv6("100::7a69:1", "fc00::1")
        .IPv6("fc00:2::1", "fc00:1::1", 64)  // Inner IPv6: hlim=64
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)    // Inner TCP: ACK flag
        .withTPR(0x0400)  // TPR ID: 1024
        .payload("katran test pkt")
  },
  //12
  {
    .description = "V6 VIP, V6 real, random TPR Id, LRU Miss, CH",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv6("fc00:2::1", "fc00:1::1")
        .TCP(31332, 80, 0, 0, 8192, TH_ACK)  // ACK flag
        .withTPR(0xFF000000)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv6("100::7a64:1", "fc00::1")
        .IPv6("fc00:2::1", "fc00:1::1", 64)  // Inner IPv6: hlim=64
        .TCP(31332, 80, 0, 0, 8192, TH_ACK)    // Inner TCP: ACK flag
        .withTPR(0xFF000000)
        .payload("katran test pkt")
  },
  //13
  {
    .description = "V6 VIP, V6 real, lots of hdr-opts, TPR Id: 1024",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv6("fc00:2::1", "fc00:1::1")
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)  // ACK flag
        .withNOP(14)  // 14 NOP options
        .withTPR(0x0400)  // TPR ID: 1024 (0x00040000)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv6("100::7a69:1", "fc00::1")
        .IPv6("fc00:2::1", "fc00:1::1", 64)  // Inner IPv6: hlim=64
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)    // Inner TCP: ACK flag
        .withNOP(14)  // 14 NOP options
        .withTPR(0x0400)  // TPR ID: 1024 (0x00040000)
        .payload("katran test pkt")
  },
  //14
  {
    .description = "packet #1 dst port hashing only",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv4("192.168.1.1", "10.200.1.4")
        .TCP(31337, 42, 0, 0, 8192, 0x10)  // ACK flag
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv4("172.16.105.122", "10.0.0.2", 64, 0, 0)
        .IPv4("192.168.1.1", "10.200.1.4", 64, 0, 1)  // Inner IPv4: TTL=64, ID=1
        .TCP(31337, 42, 0, 0, 8192, 0x10)              // Inner TCP: ACK flag
        .payload("katran test pkt")
  },
  //15
  {
    .description = "packet #2 dst port hashing only, TPR ID: 1023, bypasses LRU.",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv4("192.168.1.100", "10.200.1.4")
        .TCP(1337, 42, 0, 0, 8192, TH_ACK)  // ACK flag
        .withTPR(0x03ff)  // TPR ID: 1023 (0x000003ff)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv4("172.16.56.97", "10.0.0.2", 64, 0, 0)
        .IPv4("192.168.1.100", "10.200.1.4", 64, 0, 1)  // Inner IPv4: TTL=64, ID=1
        .TCP(1337, 42, 0, 0, 8192, TH_ACK)                 // Inner TCP: ACK flag
        .withTPR(0x03ff)  // TPR ID: 1023 (0x000003ff)
        .payload("katran test pkt")
  },
  //16
  {
    .description = "V6 VIP, V6 real, EOL before TPR, LRU hit",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv6("fc00:2::1", "fc00:1::1")
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)  // ACK flag
        .withCustomOption(0x00, std::vector<uint8_t>{})  // EOL option
        .withTPR(0x0401)  // TPR ID: 1025 (0x00000401)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv6("100::7a69:1", "fc00::1")
        .IPv6("fc00:2::1", "fc00:1::1", 64)  // Inner IPv6: hlim=64
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)    // Inner TCP: ACK flag
        .withCustomOption(0x00, std::vector<uint8_t>{})  // EOL option
        .withTPR(0x0401)  // TPR ID: 1025 (0x00000401)
        .payload("katran test pkt")
  },
  //17
  {
    .description = "V4 VIP (and v6 real), TPR Id: 1021. Invalid server id. CH",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv4("192.168.1.1", "10.200.1.3")
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)  // ACK flag
        .withNOP(4)  // 4 NOP options
        .withTPR(0x03fd)  // TPR ID: 1021 (0x000003fd)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv6("100::bac1:101", "fc00::1")
        .IPv4("192.168.1.1", "10.200.1.3", 64, 0, 1)  // Inner IPv4: TTL=64, ID=1
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)              // Inner TCP: ACK flag
        .withNOP(4)  // 4 NOP options
        .withTPR(0x03fd)  // TPR ID: 1021 (0x000003fd)
        .payload("katran test pkt")
  },
};

/**
 * TPR test fixtures with GUE encapsulation expected outputs.
 * These are the same input packets as tprTestFixtures but with 
 * expected outputs using GUE encapsulation instead of IPIP.
 */
const std::vector<PacketAttributes> tprGueTestFixtures = {
  //1
  {
    .description = "V4 VIP (and v4 real), SYN, TPR id ignored",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv4("192.168.1.1", "10.200.1.1")
        .TCP(31337, 80, 0, 0, 8192, TH_SYN)
        .withTPR(0x00000013)
        .withNOP(2)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv4("10.0.13.37", "10.0.0.3", 64, 0, 0)
        .UDP(26747, 9886)
        .IPv4("192.168.1.1", "10.200.1.1", 64, 0, 1)  // Inner IPv4: TTL=64, ID=1
        .TCP(31337, 80, 0, 0, 8192, TH_SYN)
        .withTPR(0x00000013)
        .withNOP(2)
        .payload("katran test pkt")
  },
  //2
  {
    .description = "V4 VIP (and v4 real), TPR Id: 1025",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv4("192.168.1.1", "10.200.1.1")
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)
        .withTPR(0x0401)  // TPR ID: 1025 (0x0401)
        .withNOP(2)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv4("10.0.13.37", "10.0.0.3", 64, 0, 0)
        .UDP(26747, 9886)
        .IPv4("192.168.1.1", "10.200.1.1", 64, 0, 1)  // Inner IPv4: TTL=64, ID=1
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)
        .withTPR(0x0401)  // TPR ID: 1025 (0x0401)
        .withNOP(2)
        .payload("katran test pkt")
  },
  //3
  {
    .description = "V4 VIP (and v4 real; any dst ports), TPR Id: 1023",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv4("192.168.1.1", "10.200.1.2")
        .TCP(31337, 42, 0, 0, 8192, TH_ACK)
        .withTPR(0x03ff)  // TPR ID: 1023 (0x03ff)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv4("10.0.13.37", "10.0.0.2", 64, 0, 0)
        .UDP(26747, 9886)
        .IPv4("192.168.1.1", "10.200.1.2", 64, 0, 1)  // Inner IPv4: TTL=64, ID=1
        .TCP(31337, 42, 0, 0, 8192, TH_ACK)
        .withTPR(0x03ff)  // TPR ID: 1023 (0x03ff)
        .payload("katran test pkt")
  },
  //4
  {
    .description = "V4 VIP (and v6 real), TPR Id: 1024.",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv4("192.168.1.1", "10.200.1.3")
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)
        .withNOP(4)
        .withTPR(0x0400)  // TPR ID: 1024
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv6("fc00:2307::1337", "fc00::1")
        .UDP(31592, 9886)  // GUE encapsulation uses UDP port 9886
        .IPv4("192.168.1.1", "10.200.1.3", 64, 0, 1)  // Inner IPv4: TTL=64, ID=1
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)
        .withNOP(4)
        .withTPR(0x0400)  // TPR ID: 1024
        .payload("katran test pkt")
  },
  //5
  {
    .description = "V6 VIP (and v6 real), TPR Id: 1024",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv6("fc00:2::1", "fc00:1::1")
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)
        .withTPR(0x0400)  // TPR ID: 1024 (0x0400)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv6("fc00:2307::1337", "fc00::1")
        .UDP(31337, 9886)
        .IPv6("fc00:2::1", "fc00:1::1", 64)  // Inner IPv6: hlim=64
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)
        .withTPR(0x0400)  // TPR ID: 1024 (0x0400)
        .payload("katran test pkt")
  },
  //6
  {
    .description = "V4 VIP, no TPR, LRU hit",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv4("192.168.1.1", "10.200.1.1")
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv4("10.0.13.37", "10.0.0.3", 64, 0, 0)
        .UDP(26747, 9886)
        .IPv4("192.168.1.1", "10.200.1.1", 64, 0, 1)  // Inner IPv4: TTL=64, ID=1
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)
        .payload("katran test pkt")
  },
  //7
  {
    .description = "V4 VIP, TPR Id: 1025, bypasses LRU",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv4("192.168.1.1", "10.200.1.1")
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)
        .withTPR(0x0401)  // TPR ID: 1025
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv4("10.0.13.37", "10.0.0.3", 64, 0, 0)
        .UDP(26747, 9886)
        .IPv4("192.168.1.1", "10.200.1.1", 64, 0, 1)  // Inner IPv4: TTL=64, ID=1
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)
        .withTPR(0x0401)
        .payload("katran test pkt")
  },
  //8
  {
    .description = "V6 VIP, V6 real, no TPR Id, LRU hit",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv6("fc00:2::1", "fc00:1::1")
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)  // ACK flag
        .withTimestamp(1, 3)
        .withNOP(2)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv6("fc00:2307::1337", "fc00::1")
        .UDP(31337, 9886)
        .IPv6("fc00:2::1", "fc00:1::1", 64)  // Inner IPv6: hlim=64
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)    // Inner TCP: ACK flag
        .withTimestamp(1, 3)
        .withNOP(2)
        .payload("katran test pkt")
  },
  //9
  {
    .description = "V6 VIP, V6 real, TPR Id 0, LRU hit",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv6("fc00:2::1", "fc00:1::1")
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)  // ACK flag
        .withTPR(0x0000)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv6("fc00:2307::1337", "fc00::1")
        .UDP(31337, 9886)
        .IPv6("fc00:2::1", "fc00:1::1", 64)  // Inner IPv6: hlim=64
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)    // Inner TCP: ACK flag
        .withTPR(0x0000)
        .payload("katran test pkt")
  },
  //10
  {
    .description = "V6 VIP, V6 real, TPR Id: 1024, bad hdr len, LRU hit",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv6("fc00:2::1", "fc00:1::1")
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)  // ACK flag
        .withCustomOption(0xb7, std::vector<uint8_t>{0x04, 0x00})  // Malformed TPR option
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv6("fc00:2307::1337", "fc00::1")
        .UDP(31337, 9886)
        .IPv6("fc00:2::1", "fc00:1::1", 64)  // Inner IPv6: hlim=64
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)    // Inner TCP: ACK flag
        .withCustomOption(0xb7, std::vector<uint8_t>{0x04, 0x00})  // Malformed TPR option
        .payload("katran test pkt")
  },
  //11
  {
    .description = "V6 VIP, V6 real, TPR Id: 1024, bypasses LRU",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv6("fc00:2::1", "fc00:1::1")
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)  // ACK flag
        .withTPR(0x0400)  // TPR ID: 1024
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv6("fc00:2307::1337", "fc00::1")
        .UDP(31337, 9886)
        .IPv6("fc00:2::1", "fc00:1::1", 64)  // Inner IPv6: hlim=64
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)    // Inner TCP: ACK flag
        .withTPR(0x0400)  // TPR ID: 1024
        .payload("katran test pkt")
  },
  //12
  {
    .description = "V6 VIP, V6 real, random TPR Id, LRU Miss, CH",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv6("fc00:2::1", "fc00:1::1")
        .TCP(31332, 80, 0, 0, 8192, TH_ACK)  // ACK flag
        .withTPR(0xFF000000)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv6("fc00:2307::1337", "fc00::1")
        .UDP(31332, 9886)
        .IPv6("fc00:2::1", "fc00:1::1", 64)  // Inner IPv6: hlim=64
        .TCP(31332, 80, 0, 0, 8192, TH_ACK)    // Inner TCP: ACK flag
        .withTPR(0xFF000000)
        .payload("katran test pkt")
  },
  //13
  {
    .description = "V6 VIP, V6 real, lots of hdr-opts, TPR Id: 1024",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv6("fc00:2::1", "fc00:1::1")
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)  // ACK flag
        .withNOP(14)  // 14 NOP options
        .withTPR(0x0400)  // TPR ID: 1024 (0x00040000)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv6("fc00:2307::1337", "fc00::1")
        .UDP(31337, 9886)
        .IPv6("fc00:2::1", "fc00:1::1", 64)  // Inner IPv6: hlim=64
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)    // Inner TCP: ACK flag
        .withNOP(14)  // 14 NOP options
        .withTPR(0x0400)  // TPR ID: 1024 (0x00040000)
        .payload("katran test pkt")
  },
  //14
  {
    .description = "packet #1 dst port hashing only",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv4("192.168.1.1", "10.200.1.4")
        .TCP(31337, 42, 0, 0, 8192, 0x10)  // ACK flag
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv4("10.0.13.37", "10.0.0.2", 64, 0, 0)
        .UDP(27002, 9886)
        .IPv4("192.168.1.1", "10.200.1.4", 64, 0, 1)  // Inner IPv4: TTL=64, ID=1
        .TCP(31337, 42, 0, 0, 8192, 0x10)              // Inner TCP: ACK flag
        .payload("katran test pkt")
  },
  //15
  {
    .description = "packet #2 dst port hashing only, TPR ID: 1023, bypasses LRU.",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv4("192.168.1.100", "10.200.1.4")
        .TCP(1337, 42, 0, 0, 8192, TH_ACK)  // ACK flag
        .withTPR(0x03ff)  // TPR ID: 1023 (0x000003ff)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv4("10.0.13.37", "10.0.0.2", 64, 0, 0)
        .UDP(14433, 9886)
        .IPv4("192.168.1.100", "10.200.1.4", 64, 0, 1)  // Inner IPv4: TTL=64, ID=1
        .TCP(1337, 42, 0, 0, 8192, TH_ACK)                 // Inner TCP: ACK flag
        .withTPR(0x03ff)  // TPR ID: 1023 (0x000003ff)
        .payload("katran test pkt")
  },
  //16
  {
    .description = "V6 VIP, V6 real, EOL before TPR, LRU hit",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv6("fc00:2::1", "fc00:1::1")
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)  // ACK flag
        .withCustomOption(0x00, std::vector<uint8_t>{})  // EOL option
        .withTPR(0x0401)  // TPR ID: 1025 (0x00000401)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv6("fc00:2307::1337", "fc00::1")
        .UDP(31337, 9886)
        .IPv6("fc00:2::1", "fc00:1::1", 64)  // Inner IPv6: hlim=64
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)    // Inner TCP: ACK flag
        .withCustomOption(0x00, std::vector<uint8_t>{})  // EOL option
        .withTPR(0x0401)  // TPR ID: 1025 (0x00000401)
        .payload("katran test pkt")
  },
  //17
  {
    .description = "V4 VIP (and v6 real), TPR Id: 1021. Invalid server id. CH",
    .expectedReturnValue = "XDP_TX",
    .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("0x1", "0x2")
        .IPv4("192.168.1.1", "10.200.1.3")
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)  // ACK flag
        .withNOP(4)  // 4 NOP options
        .withTPR(0x03fd)  // TPR ID: 1021 (0x000003fd)
        .payload("katran test pkt"),
    .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
        .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
        .IPv6("fc00:2307::1337", "fc00::1")
        .UDP(31592, 9886)
        .IPv4("192.168.1.1", "10.200.1.3", 64, 0, 1)  // Inner IPv4: TTL=64, ID=1
        .TCP(31337, 80, 0, 0, 8192, TH_ACK)              // Inner TCP: ACK flag
        .withNOP(4)  // 4 NOP options
        .withTPR(0x03fd)  // TPR ID: 1021 (0x000003fd)
        .payload("katran test pkt")
  }
};

} // namespace testing
} // namespace katran
