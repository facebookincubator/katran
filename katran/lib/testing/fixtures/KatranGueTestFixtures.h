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
#include <string>
#include <vector>
#include "katran/lib/testing/tools/PacketAttributes.h"
#include "katran/lib/testing/tools/PacketBuilder.h"

namespace katran {
namespace testing {
/**
 * input packets has been generated with scapy. above each of em you can find
 * a command which has been used to do so.
 *
 * format of the input data: <string, string>; 1st string is a base64 encoded
 * packet. 2nd string is test's description
 *
 * format of the output data: <string, string>; 1st string is a base64 encoded
 * packet which we are expecting to see after bpf program's run.
 * 2nd string = bpf's program return code.
 *
 * to create pcap w/ scapy:
 * 1) create packets
 * 2) pckts = [ <created packets from above> ]
 * 3) wrpcap(<path_to_file>, pckts)
 */
const std::vector<::katran::PacketAttributes> gueTestFixtures = {
    // 1
    { .description = "packet to UDP based v4 VIP (and v4 real)",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv4("192.168.1.1", "10.200.1.1")
         .UDP(31337, 80)
         .payload("katran test pkt"),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
         .IPv4("10.0.13.37", "10.0.0.3", 64, 0, 0)
         .UDP(26747, 9886)
         .IPv4("192.168.1.1", "10.200.1.1")
         .UDP(31337, 80)
         .payload("katran test pkt")
    },
    // 2
    { .description = "packet to TCP based v4 VIP (and v4 real)",
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
         .IPv4("192.168.1.1", "10.200.1.1")
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt")
    },
    // 3
    {.description = "packet to TCP based v4 VIP (and v4 real; any dst ports).",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv4("192.168.1.1", "10.200.1.2")
         .TCP(31337, 42, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt"),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
         .IPv4("10.0.13.37", "10.0.0.2", 64, 0, 0)
         .UDP(26747, 9886)
         .IPv4("192.168.1.1", "10.200.1.2")
         .TCP(31337, 42, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt")
    },
    // 4
    {.description = "packet to TCP based v4 VIP (and v6 real)",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv4("192.168.1.1", "10.200.1.3")
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt"),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
         .IPv6("fc00:2307::1337", "fc00::1", 64, 0, 0)
         .UDP(31592, 9886)
         .IPv4("192.168.1.1", "10.200.1.3")
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt")
    },
    // 5
    {.description = "packet to TCP based v6 VIP (and v6 real)",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv6("fc00:2::1", "fc00:1::1")
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt"),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
         .IPv6("fc00:2307::1337", "fc00::3", 64, 0, 0)
         .UDP(31337, 9886)
         .IPv6("fc00:2::1", "fc00:1::1")
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt")
    },
    // 6
    {.description = "v4 ICMP echo-request",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
                               .Eth("0x1", "0x2")
                               .IPv4("192.168.1.1", "10.200.1.3")
                               .ICMP(ICMPv4Header::ECHO_REQUEST),
     .expectedOutputPacketBuilder =
         katran::testing::PacketBuilder::newPacket()
             .Eth("02:00:00:00:00:00", "01:00:00:00:00:00")
             .IPv4("10.200.1.3", "192.168.1.1")
             .ICMP(ICMPv4Header::ECHO_REPLY)},
    // 7
    {.description = "v6 ICMP echo-request",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
                               .Eth("0x1", "0x2")
                               .IPv6("fc00:2::1", "fc00:1::1")
                               .ICMPv6(ICMPv6Header::ECHO_REQUEST),
     .expectedOutputPacketBuilder =
         katran::testing::PacketBuilder::newPacket()
             .Eth("02:00:00:00:00:00", "01:00:00:00:00:00")
             .IPv6("fc00:1::1", "fc00:2::1")
             .ICMPv6(ICMPv6Header::ECHO_REPLY)},
     // 8
    {.description = "v4 ICMP dest-unreachabe fragmentation-needed",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder =
         katran::testing::PacketBuilder::newPacket()
             .Eth("01:00:00:00:00:00", "02:00:00:00:00:00")
             .IPv4("192.168.100.1", "10.200.1.1")
             .ICMP(ICMPv4Header::DEST_UNREACH, ICMPv4Header::FRAG_NEEDED, 0, 0)
             .IPv4("10.200.1.1", "192.168.1.1")
             .TCP(80, 31337, 0, 0, 8192, TH_SYN)
             .payload("test katran pkt"),
     .expectedOutputPacketBuilder =
         katran::testing::PacketBuilder::newPacket()
             .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
             .IPv4("10.0.13.37", "10.0.0.3", 64, 0, 0, 0, 5)
             .UDP(26747, 9886)
             .IPv4("192.168.100.1", "10.200.1.1")
             .ICMP(ICMPv4Header::DEST_UNREACH, ICMPv4Header::FRAG_NEEDED, 0, 0)
             .IPv4("10.200.1.1", "192.168.1.1")
             .TCP(80, 31337, 0, 0, 8192, TH_SYN)
             .payload("test katran pkt")},
    // 9
    {.description = "v6 ICMP packet-too-big",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
                               .Eth("0x1", "0x2")
                               .IPv6("fc00:200::1", "fc00:1::1")
                               .ICMPv6(ICMPv6Header::PACKET_TOO_BIG, 0, 0, 1280)
                               .IPv6("fc00:1::1", "fc00:2::1")
                               .TCP(80, 31337, 0, 0, 8192, TH_SYN)
                               .payload("katran test packet"),
     .expectedOutputPacketBuilder =
         katran::testing::PacketBuilder::newPacket()
             .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
             .IPv6("fc00:2307::1337", "fc00::3")
             .UDP(31337, 9886)
             .IPv6("fc00:200::1", "fc00:1::1")
             .ICMPv6(ICMPv6Header::PACKET_TOO_BIG, 0, 0, 1280)
             .IPv6("fc00:1::1", "fc00:2::1")
             .TCP(80, 31337, 0, 0, 8192, TH_SYN)
             .payload("katran test packet")},
    // 10
    {.description = "drop of IPv4 packet w/ options",
     .expectedReturnValue = "XDP_DROP",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv4("192.168.1.1", "10.200.1.1", 64, 0, 1, 0, 6)
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt"),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv4("192.168.1.1", "10.200.1.1", 64, 0, 1, 0, 6)
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt")
    },
    // 11
    {.description = "drop of IPv4 fragmented packet",
     .expectedReturnValue = "XDP_DROP",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv4("192.168.1.1", "10.200.1.1", 64, 0, 1, PacketBuilder::IP_FLAG_MF)
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt"),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv4("192.168.1.1", "10.200.1.1", 64, 0, 1, PacketBuilder::IP_FLAG_MF)
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt")
    },
    // 12
    {.description = "drop of IPv6 fragmented packet",
     .expectedReturnValue = "XDP_DROP",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv6("fc00:2::1", "fc00:1::1", 64, 0, 0, PacketBuilder::IPV6_NH_FRAGMENT)
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt"),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv6("fc00:2::1", "fc00:1::1", 64, 0, 0, PacketBuilder::IPV6_NH_FRAGMENT)
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt")
    },
    // 13
    {.description = "pass of v4 packet with dst not equal to any configured VIP",
     .expectedReturnValue = "XDP_PASS",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv4("192.168.1.1", "10.200.1.1")
         .TCP(31337, 82, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt"),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv4("192.168.1.1", "10.200.1.1")
         .TCP(31337, 82, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt")
    },
    // 14
    {.description = "pass of v6 packet with dst not equal to any configured VIP",
     .expectedReturnValue = "XDP_PASS",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv6("fc00:2::1", "fc00:1::1")
         .TCP(31337, 82, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt"),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv6("fc00:2::1", "fc00:1::1")
         .TCP(31337, 82, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt")
    },
    // 15
    {.description = "pass of arp packet",
     .expectedReturnValue = "XDP_PASS",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .ARP(),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .ARP()
    },
    // 16
    {.description = "LRU hit",
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
         .IPv4("192.168.1.1", "10.200.1.1")
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt")
    },
    // 17
    {.description = "packet #1 dst port hashing only",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv4("192.168.1.1", "10.200.1.4")
         .TCP(31337, 42, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt"),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
         .IPv4("10.0.13.37", "10.0.0.2", 64, 0, 0)
         .UDP(27002, 9886)
         .IPv4("192.168.1.1", "10.200.1.4")
         .TCP(31337, 42, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt")
    },
    // 18
    {.description = "packet #2 dst port hashing only",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv4("192.168.1.100", "10.200.1.4")
         .TCP(1337, 42, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt"),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
         .IPv4("10.0.13.37", "10.0.0.2", 64, 0, 0)
         .UDP(14597, 9886)
         .IPv4("192.168.1.100", "10.200.1.4")
         .TCP(1337, 42, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt")
    },
    // 19
    {.description = "gue ipv4 inner ipv4 outer packet",
     .expectedReturnValue = "XDP_PASS",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv4("172.16.1.1", "172.16.100.1")
         .UDP(1337, 6080)
         .IPv4("192.168.1.1", "10.200.1.1")
         .UDP(31337, 80)
         .payload("katran test pkt"),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv4("172.16.1.1", "172.16.100.1")
         .UDP(1337, 6080)
         .IPv4("192.168.1.1", "10.200.1.1")
         .UDP(31337, 80)
         .payload("katran test pkt")
    },
    // 20
    {.description = "gue ipv6 inner ipv6 outer packet",
     .expectedReturnValue = "XDP_PASS",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv6("100::1", "100::2")
         .UDP(1337, 6080)
         .IPv6("fc00:2::1", "fc00:1::1")
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt"),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv6("100::1", "100::2")
         .UDP(1337, 6080)
         .IPv6("fc00:2::1", "fc00:1::1")
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt")
    },
    // 21
    {.description = "gue ipv4 inner ipv6 outer packet",
     .expectedReturnValue = "XDP_PASS",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv6("100::1", "100::2")
         .UDP(1337, 6080)
         .IPv4("192.168.1.1", "10.200.1.1")
         .UDP(31337, 80)
         .payload("katran test pkt"),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv6("100::1", "100::2")
         .UDP(1337, 6080)
         .IPv4("192.168.1.1", "10.200.1.1")
         .UDP(31337, 80)
         .payload("katran test pkt")
    },
    // 22
    {.description = "QUIC: long header. Client Initial type. LRU miss",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv4("192.168.1.42", "10.200.1.5")
         .UDP(31337, 443)
         .QUICInitial()
         .destConnId({0x41, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00})
         .version(QUIC_V1_WIRE_FORMAT)
         .token({0x11})
         .packetNumber(0x11, 1)
         .data("quic data\x00@")
         .done(),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
         .IPv4("10.0.13.37", "10.0.0.2", 64, 0, 0)
         .UDP(26704, 9886)
         .IPv4("192.168.1.42", "10.200.1.5")
         .UDP(31337, 443)
         .QUICInitial()
         .destConnId({0x41, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00})
         .version(QUIC_V1_WIRE_FORMAT)
         .token({0x11})
         .packetNumber(0x11, 1)
         .data("quic data\x00@")
         .done()
    },
    // 23
    {.description = "QUIC: long header. 0-RTT Protected. CH. LRU hit.",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv4("192.168.1.42", "10.200.1.5")
         .UDP(31337, 443)
         .QUIC0RTT()
         .destConnId({0x43, 0xFF, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})
         .version(QUIC_V1_WIRE_FORMAT)
         .packetNumber(0x11, 1)
         .data("\x01quic data")
         .done(),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
         .IPv4("10.0.13.37", "10.0.0.2", 64, 0, 0)
         .UDP(26704, 9886)
         .IPv4("192.168.1.42", "10.200.1.5")
         .UDP(31337, 443)
         .QUIC0RTT()
         .destConnId({0x43, 0xFF, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})
         .version(QUIC_V1_WIRE_FORMAT)
         .packetNumber(0x11, 1)
         .data("\x01quic data")
         .done()
    },
    // 24
    {.description = "QUIC: long header. Handshake. v4 vip v6 real. Conn Id V1 based. server id is 1024 mapped to fc00::1.",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv4("192.168.1.42", "10.200.1.5")
         .UDP(31337, 443)
         .QUICHandshake()
         .destConnId({0x41, 0x00, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00})
         .version(QUIC_V1_WIRE_FORMAT)
         .packetNumber(0x11, 1)
         .data("\x01quic data\x00@")
         .done(),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
         .IPv6("fc00:2307::1337", "fc00::1", 64, 0, 0)
         .UDP(31555, 9886)
         .IPv4("192.168.1.42", "10.200.1.5")
         .UDP(31337, 443)
         .QUICHandshake()
         .destConnId({0x41, 0x00, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00})
         .version(QUIC_V1_WIRE_FORMAT)
         .packetNumber(0x11, 1)
         .data("\x01quic data\x00@")
         .done()
    },
    // 25
    {.description = "QUIC: long header. Retry. v4 vip v6 real. Conn Id V1 based. server id is 1024 mapped to fc00::1.",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv4("192.168.1.42", "10.200.1.5")
         .UDP(31337, 443)
         .QUICRetry()
         .destConnId({0x41, 0x00, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00})
         .version(QUIC_V1_WIRE_FORMAT)
         .data("\x01\x11\x01quic data\x00@")
         .done(),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
         .IPv6("fc00:2307::1337", "fc00::1", 64, 0, 0)
         .UDP(31555, 9886)
         .IPv4("192.168.1.42", "10.200.1.5")
         .UDP(31337, 443)
         .QUICRetry()
         .destConnId({0x41, 0x00, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00})
         .version(QUIC_V1_WIRE_FORMAT)
         .data("\x01\x11\x01quic data\x00@")
         .done()
    },
    // 26
    {.description = "QUIC: long header. client initial. v6 vip v6 real. LRU miss",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv6("fc00:2::42", "fc00:1::2")
         .UDP(31337, 443)
         .QUICInitial()
         .destConnId({0x44, 0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00})
         .version(QUIC_V1_WIRE_FORMAT)
         .token({0x11})
         .packetNumber(0x11, 1)
         .data("\x01quic data\x00@")
         .done(),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
         .IPv6("fc00:2307::1337", "fc00::1", 64, 0, 0)
         .UDP(31337, 9886)
         .IPv6("fc00:2::42", "fc00:1::2")
         .UDP(31337, 443)
         .QUICInitial()
         .destConnId({0x44, 0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00})
         .version(QUIC_V1_WIRE_FORMAT)
         .token({0x11})
         .packetNumber(0x11, 1)
         .data("\x01quic data\x00@")
         .done()
    },
    // 27
    {.description = "QUIC: short header. No connection id. CH. LRU hit",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv4("192.168.1.42", "10.200.1.5")
         .UDP(31337, 443)
         .payload(std::string("\x00", 1)),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
         .IPv6("fc00:2307::1337", "fc00::1", 64, 0, 0)
         .UDP(31555, 9886)
         .IPv4("192.168.1.42", "10.200.1.5")
         .UDP(31337, 443)
         .payload(std::string("\x00", 1))
    },
    // 28
    {.description = "QUIC: short header w/ connection id",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv4("192.168.1.42", "10.200.1.5")
         .UDP(31337, 443)
         .QUICShortHeader()
         .destConnId({0x41, 0x00, 0x83, 0x04, 0x05, 0x06, 0x07, 0x00})
         .cidVersion(QUICHeader::CID_V1)
         .data("@")
         .done(),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
         .IPv6("fc00:2307::1337", "fc00::2", 64, 0, 0)
         .UDP(31555, 9886)
         .IPv4("192.168.1.42", "10.200.1.5")
         .UDP(31337, 443)
         .QUICShortHeader()
         .destConnId({0x41, 0x00, 0x83, 0x04, 0x05, 0x06, 0x07, 0x00})
         .cidVersion(QUICHeader::CID_V1)
         .data("@")
         .done()
    },
    // 29
    {.description = "QUIC: short header w/ connection 1092 id but non-existing mapping. LRU hit",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv4("192.168.1.42", "10.200.1.5")
         .UDP(31337, 443)
         .QUICShortHeader()
         .destConnId({0x41, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
         .cidVersion(QUICHeader::CID_V1)
         .data("@")
         .done(),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
         .IPv6("fc00:2307::1337", "fc00::2", 64, 0, 0)
         .UDP(31555, 9886)
         .IPv4("192.168.1.42", "10.200.1.5")
         .UDP(31337, 443)
         .QUICShortHeader()
         .destConnId({0x41, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
         .cidVersion(QUICHeader::CID_V1)
         .data("@")
         .done()
    },
    // 30
    {.description = "QUIC: short header w/ conn id. host id = 0. CH. LRU hit",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv4("192.168.1.42", "10.200.1.5")
         .UDP(31337, 443)
         .QUICShortHeader()
         .destConnId({0x40, 0x00, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00})
         .cidVersion(QUICHeader::CID_V1)
         .data("@")
         .done(),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
         .IPv6("fc00:2307::1337", "fc00::2", 64, 0, 0)
         .UDP(31555, 9886)
         .IPv4("192.168.1.42", "10.200.1.5")
         .UDP(31337, 443)
         .QUICShortHeader()
         .destConnId({0x40, 0x00, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00})
         .cidVersion(QUICHeader::CID_V1)
         .data("@")
         .done()
    },
    // 31
    {.description = "packet to TCP based v4 VIP (and v4 real) + ToS in IPV4",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv4("192.168.1.1", "10.200.1.1", 64, 0x8c)
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt"),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
         .IPv4("10.0.13.37", "10.0.0.3", 64, 0x8c, 0)
         .UDP(26747, 9886)
         .IPv4("192.168.1.1", "10.200.1.1", 64, 0x8c)
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt")
    },
    // 32
    {.description = "packet to TCP based v6 VIP (and v6 real) with ToS / tc set",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv6("fc00:2::1", "fc00:1::1", 64, 0x8c)
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt"),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
         .IPv6("fc00:2307::1337", "fc00::3", 64, 0x8c, 0)
         .UDP(31337, 9886)
         .IPv6("fc00:2::1", "fc00:1::1", 64, 0x8c)
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt")
    },
    // 33
    {.description = "QUIC: short header w/ connection id. CIDv2",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv4("192.168.1.42", "10.200.1.5")
         .UDP(31337, 443)
         .QUICShortHeader()
         .destConnId({0x80, 0x03, 0x04, 0x02, 0x05, 0x06, 0x07, 0x00})
         .cidVersion(QUICHeader::CID_V2)
         .data("@")
         .done(),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
         .IPv6("fc00:2307::1337", "fc00::2", 64, 0, 0)
         .UDP(31555, 9886)
         .IPv4("192.168.1.42", "10.200.1.5")
         .UDP(31337, 443)
         .QUICShortHeader()
         .destConnId({0x80, 0x03, 0x04, 0x02, 0x05, 0x06, 0x07, 0x00})
         .cidVersion(QUICHeader::CID_V2)
         .data("@")
         .done()
    },
    // 34
    {.description = "QUIC: short header w/ connection id 197700 but non-existing mapping. CIDv2. LRU hit.",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv4("192.168.1.42", "10.200.1.5")
         .UDP(31337, 443)
         .QUICShortHeader()
         .destConnId({0x80, 0x03, 0x04, 0x44, 0x00, 0x00, 0x00, 0x00})
         .cidVersion(QUICHeader::CID_V2)
         .data("@")
         .done(),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
         .IPv6("fc00:2307::1337", "fc00::2", 64, 0, 0)
         .UDP(31555, 9886)
         .IPv4("192.168.1.42", "10.200.1.5")
         .UDP(31337, 443)
         .QUICShortHeader()
         .destConnId({0x80, 0x03, 0x04, 0x44, 0x00, 0x00, 0x00, 0x00})
         .cidVersion(QUICHeader::CID_V2)
         .data("@")
         .done()
    },
    // 35
    {.description = "packet to TCP based v4 VIP that is not initialzed",
     .expectedReturnValue = "XDP_DROP",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv4("192.168.1.1", "10.200.1.99")
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt"),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv4("192.168.1.1", "10.200.1.99")
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt")
    },
    // 36
    {.description = "packet to UDP based v6 VIP that is not initialized",
     .expectedReturnValue = "XDP_DROP",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv6("fc00:2::1", "fc00:1::11")
         .UDP(31337, 80)
         .payload("katran test"),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv6("fc00:2::1", "fc00:1::11")
         .UDP(31337, 80)
         .payload("katran test")
    },
};

} // namespace testing
} // namespace katran
