// @nolint

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
#include <vector>
#include "katran/lib/testing/tools/PacketAttributes.h"

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
 *
 * to get base64 packet string: base64.b64encode(raw(packet))
 * to get packet from base64 string: Ether(base64.b64decode(b"..."))
 */
const std::vector<katran::PacketAttributes> testFixtures = {
    // 1
    {.description = "packet to UDP based v4 VIP (and v4 real)",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
                               .Eth("0x1", "0x2")
                               .IPv4("192.168.1.1", "10.200.1.1")
                               .UDP(31337, 80)
                               .payload("katran test pkt"),
     .expectedOutputPacketBuilder =
         katran::testing::PacketBuilder::newPacket()
             .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
             .IPv4("172.16.104.123", "10.0.0.3", 64, 0, 0)
             .IPv4("192.168.1.1", "10.200.1.1")
             .UDP(31337, 80)
             .payload("katran test pkt")},
    // 2
    {.description = "packet to TCP based v4 VIP (and v4 real)",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
                               .Eth("0x1", "0x2")
                               .IPv4("192.168.1.1", "10.200.1.1")
                               .TCP(31337, 80, 0, 0, 8192, TH_ACK)
                               .payload("katran test pkt"),
     .expectedOutputPacketBuilder =
         katran::testing::PacketBuilder::newPacket()
             .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
             .IPv4("172.16.104.123", "10.0.0.3", 64, 0, 0)
             .IPv4("192.168.1.1", "10.200.1.1")
             .TCP(31337, 80, 0, 0, 8192, TH_ACK)
             .payload("katran test pkt")},
    // 3
    {.description = "packet to TCP based v4 VIP (and v4 real) + ToS in IPV4",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
                               .Eth("0x1", "0x2")
                               .IPv4("192.168.1.1", "10.200.1.1", 64, 0x8c)
                               .TCP(31337, 80, 0, 0, 8192, TH_ACK)
                               .payload("katran test pkt"),
     .expectedOutputPacketBuilder =
         katran::testing::PacketBuilder::newPacket()
             .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
             .IPv4("172.16.104.123", "10.0.0.3", 64, 0x8c, 0)
             .IPv4("192.168.1.1", "10.200.1.1", 64, 0x8c)
             .TCP(31337, 80, 0, 0, 8192, TH_ACK)
             .payload("katran test pkt")},
    // 4
    {.description = "packet to TCP based v4 VIP (and v4 real; any dst ports).",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
                               .Eth("0x1", "0x2")
                               .IPv4("192.168.1.1", "10.200.1.2")
                               .TCP(31337, 42, 0, 0, 8192, TH_ACK)
                               .payload("katran test pkt"),
     .expectedOutputPacketBuilder =
         katran::testing::PacketBuilder::newPacket()
             .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
             .IPv4("172.16.104.123", "10.0.0.2", 64, 0, 0)
             .IPv4("192.168.1.1", "10.200.1.2")
             .TCP(31337, 42, 0, 0, 8192, TH_ACK)
             .payload("katran test pkt")},
    // 5
    {.description = "packet to TCP based v4 VIP (and v6 real)",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
                               .Eth("0x1", "0x2")
                               .IPv4("192.168.1.1", "10.200.1.3")
                               .TCP(31337, 80, 0, 0, 8192, TH_ACK)
                               .payload("katran test pkt"),
     .expectedOutputPacketBuilder =
         katran::testing::PacketBuilder::newPacket()
             .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
             .IPv6("100::bac1:101", "fc00::1")
             .IPv4("192.168.1.1", "10.200.1.3")
             .TCP(31337, 80, 0, 0, 8192, TH_ACK)
             .payload("katran test pkt")},
    // 6
    {.description = "packet to TCP based v6 VIP (and v6 real)",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
                               .Eth("0x1", "0x2")
                               .IPv6("fc00:2::1", "fc00:1::1")
                               .TCP(31337, 80, 0, 0, 8192, TH_ACK)
                               .payload("katran test pkt"),
     .expectedOutputPacketBuilder =
         katran::testing::PacketBuilder::newPacket()
             .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
             .IPv6("100::7a69:1", "fc00::3")
             .IPv6("fc00:2::1", "fc00:1::1")
             .TCP(31337, 80, 0, 0, 8192, TH_ACK)
             .payload("katran test pkt")},
    // 7
    {.description =
         "packet to TCP based v6 VIP (and v6 real) with ToS / tc set",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
                               .Eth("0x1", "0x2")
                               .IPv6("fc00:2::1", "fc00:1::1", 64, 0x8c)
                               .TCP(31337, 80, 0, 0, 8192, TH_ACK)
                               .payload("katran test pkt"),
     .expectedOutputPacketBuilder =
         katran::testing::PacketBuilder::newPacket()
             .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
             .IPv6("100::7a69:1", "fc00::3", 64, 0x8c)
             .IPv6("fc00:2::1", "fc00:1::1", 64, 0x8c)
             .TCP(31337, 80, 0, 0, 8192, TH_ACK)
             .payload("katran test pkt")},
    // 8
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
    // 9
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
    // 10
    {.description = "v4 ICMP dest-unreachabe fragmentation-needed",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder =
         katran::testing::PacketBuilder::newPacket()
             .Eth("0x1", "0x2")
             .IPv4("192.168.100.1", "10.200.1.1")
             .ICMP(ICMPv4Header::DEST_UNREACH, ICMPv4Header::FRAG_NEEDED, 0, 0)
             .IPv4("10.200.1.1", "192.168.1.1")
             .TCP(80, 31337, 0, 0, 8192, TH_SYN)
             .payload("test katran pkt"),
     .expectedOutputPacketBuilder =
         katran::testing::PacketBuilder::newPacket()
             .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
             .IPv4("172.16.104.123", "10.0.0.3", 64, 0, 0)
             .IPv4("192.168.100.1", "10.200.1.1")
             .ICMP(ICMPv4Header::DEST_UNREACH, ICMPv4Header::FRAG_NEEDED, 0, 0)
             .IPv4("10.200.1.1", "192.168.1.1")
             .TCP(80, 31337, 0, 0, 8192, TH_SYN)
             .payload("test katran pkt")},
    // 11
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
             .IPv6("100::7a69:1", "fc00::3")
             .IPv6("fc00:200::1", "fc00:1::1")
             .ICMPv6(ICMPv6Header::PACKET_TOO_BIG, 0, 0, 1280)
             .IPv6("fc00:1::1", "fc00:2::1")
             .TCP(80, 31337, 0, 0, 8192, TH_SYN)
             .payload("katran test packet")},
    // 12
    {.description = "drop of IPv4 packet w/ options",
     .expectedReturnValue = "XDP_DROP",
     .inputPacketBuilder =
         katran::testing::PacketBuilder::newPacket()
             .Eth("0x1", "0x2")
             .IPv4("192.168.1.1", "10.200.1.1", 64, 0, 1, 0, 6)
             .TCP(31337, 80, 0, 0, 8192, TH_ACK)
             .payload("katran test pkt"),
     .expectedOutputPacketBuilder =
         katran::testing::PacketBuilder::newPacket()
             .Eth("0x1", "0x2")
             .IPv4("192.168.1.1", "10.200.1.1", 64, 0, 1, 0, 6)
             .TCP(31337, 80, 0, 0, 8192, TH_ACK)
             .payload("katran test pkt")},
    // 13
    {.description = "drop of IPv4 fragmented packet",
     .expectedReturnValue = "XDP_DROP",
     .inputPacketBuilder = PacketBuilder::newPacket()
                               .Eth("0x1", "0x2")
                               .IPv4("192.168.1.1", "10.200.1.1", 64, 0, 1, PacketBuilder::IP_FLAG_MF)
                               .TCP(31337, 80, 0, 0, 8192, TH_ACK)
                               .payload("katran test pkt"),
     .expectedOutputPacketBuilder = PacketBuilder::newPacket()
                                        .Eth("0x1", "0x2")
                                        .IPv4("192.168.1.1", "10.200.1.1", 64, 0, 1, PacketBuilder::IP_FLAG_MF)
                                        .TCP(31337, 80, 0, 0, 8192, TH_ACK)
                                        .payload("katran test pkt")},
    // 14
    {.description = "drop of IPv6 fragmented packet",
     .expectedReturnValue = "XDP_DROP",
     .inputPacketBuilder = PacketBuilder::newPacket()
                               .Eth("0x1", "0x2")
                               .IPv6("fc00:2::1", "fc00:1::1", 64, 0, 0, PacketBuilder::IPV6_NH_FRAGMENT)
                               .TCP(31337, 80, 0, 0, 8192, TH_ACK)
                               .payload("katran test pkt"),
     .expectedOutputPacketBuilder = PacketBuilder::newPacket()
                                        .Eth("0x1", "0x2")
                                        .IPv6("fc00:2::1", "fc00:1::1", 64, 0, 0, PacketBuilder::IPV6_NH_FRAGMENT)
                                        .TCP(31337, 80, 0, 0, 8192, TH_ACK)
                                        .payload("katran test pkt")},
    // 15
    {.description =
         "pass of v4 packet with dst not equal to any configured VIP",
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
                                        .payload("katran test pkt")},
    // 16
    {.description =
         "pass of v6 packet with dst not equal to any configured VIP",
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
                                        .payload("katran test pkt")},
    // 17
    {.description = "pass of arp packet",
     .expectedReturnValue = "XDP_PASS",
     .inputPacketBuilder =
         katran::testing::PacketBuilder::newPacket().Eth("0x1", "0x2").ARP(),
     .expectedOutputPacketBuilder =
         katran::testing::PacketBuilder::newPacket().Eth("0x1", "0x2").ARP()},
    // 18
    {.description = "LRU hit",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
                               .Eth("0x1", "0x2")
                               .IPv4("192.168.1.1", "10.200.1.1")
                               .TCP(31337, 80, 0, 0, 8192, TH_ACK)
                               .payload("katran test pkt"),
     .expectedOutputPacketBuilder =
         katran::testing::PacketBuilder::newPacket()
             .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
             .IPv4("172.16.104.123", "10.0.0.3", 64, 0, 0)
             .IPv4("192.168.1.1", "10.200.1.1")
             .TCP(31337, 80, 0, 0, 8192, TH_ACK)
             .payload("katran test pkt")},
    // 19
    {.description = "packet #1 dst port hashing only",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
                               .Eth("0x1", "0x2")
                               .IPv4("192.168.1.1", "10.200.1.4")
                               .TCP(31337, 42, 0, 0, 8192, TH_ACK)
                               .payload("katran test pkt"),
     .expectedOutputPacketBuilder =
         katran::testing::PacketBuilder::newPacket()
             .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
             .IPv4("172.16.105.122", "10.0.0.2", 64, 0, 0)
             .IPv4("192.168.1.1", "10.200.1.4")
             .TCP(31337, 42, 0, 0, 8192, TH_ACK)
             .payload("katran test pkt")},
    // 20
    {.description = "packet #2 dst port hashing only",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
                               .Eth("0x1", "0x2")
                               .IPv4("192.168.1.100", "10.200.1.4")
                               .TCP(1337, 42, 0, 0, 8192, TH_ACK)
                               .payload("katran test pkt"),
     .expectedOutputPacketBuilder =
         katran::testing::PacketBuilder::newPacket()
             .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
             .IPv4("172.16.57.5", "10.0.0.2", 64, 0, 0)
             .IPv4("192.168.1.100", "10.200.1.4")
             .TCP(1337, 42, 0, 0, 8192, TH_ACK)
             .payload("katran test pkt")},
    // 21
    {.description = "ipinip packet",
     .expectedReturnValue = "XDP_PASS",
     .inputPacketBuilder =
         katran::testing::PacketBuilder::newPacket()
             .Eth("0x1", "0x2")
             .IPv4("172.16.1.1", "172.16.100.1", 64, 0, 1, 0, 5)
             .IPv4("192.168.1.1", "10.200.1.1")
             .UDP(31337, 80)
             .payload("katran test pkt"),
     .expectedOutputPacketBuilder =
         katran::testing::PacketBuilder::newPacket()
             .Eth("0x1", "0x2")
             .IPv4("172.16.1.1", "172.16.100.1", 64, 0, 1, 0, 5)
             .IPv4("192.168.1.1", "10.200.1.1")
             .UDP(31337, 80)
             .payload("katran test pkt")},
    // 22
    {.description = "ipv6inipv6 packet",
     .expectedReturnValue = "XDP_PASS",
     .inputPacketBuilder =
         katran::testing::PacketBuilder::newPacket()
             .Eth("0x1", "0x2")
             .IPv6("100::1", "100::2", 64, 0, 0, 41) // nextHeader=41
             // (IPv6)
             .IPv6("fc00:2::1", "fc00:1::1")
             .TCP(31337, 80, 0, 0, 8192, TH_ACK)
             .payload("katran test pkt"),
     .expectedOutputPacketBuilder =
         katran::testing::PacketBuilder::newPacket()
             .Eth("0x1", "0x2")
             .IPv6("100::1", "100::2", 64, 0, 0, 41) // nextHeader=41
             // (IPv6)
             .IPv6("fc00:2::1", "fc00:1::1")
             .TCP(31337, 80, 0, 0, 8192, TH_ACK)
             .payload("katran test pkt")},
    // 23
    {.description = "ipv4inipv6 packet",
     .expectedReturnValue = "XDP_PASS",
     .inputPacketBuilder =
         katran::testing::PacketBuilder::newPacket()
             .Eth("0x1", "0x2")
             .IPv6("100::1", "100::2", 64, 0, 0, 4) // nextHeader=4 (IPv4)
             .IPv4("192.168.1.1", "10.200.1.1")
             .UDP(31337, 80)
             .payload("katran test pkt"),
     .expectedOutputPacketBuilder =
         katran::testing::PacketBuilder::newPacket()
             .Eth("0x1", "0x2")
             .IPv6("100::1", "100::2", 64, 0, 0, 4) // nextHeader=4 (IPv4)
             .IPv4("192.168.1.1", "10.200.1.1")
             .UDP(31337, 80)
             .payload("katran test pkt")},
    // 24
    {.description = "QUIC: long header. Client Initial type. LRU miss",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder =
         PacketBuilder::newPacket()
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
     .expectedOutputPacketBuilder =
         PacketBuilder::newPacket()
             .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
             .IPv4("172.16.104.80", "10.0.0.2", 64, 0, 0) // Outer IPv4
             // encapsulation
             .IPv4("192.168.1.42", "10.200.1.5") // Inner IPv4
             .UDP(31337, 443)
             .QUICInitial()
             .destConnId({0x41, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00})
             .version(QUIC_V1_WIRE_FORMAT)
             .token({0x11})
             .packetNumber(0x11, 1)
             .data("quic data\x00@")
             .done()},
    // 25
    {.description = "QUIC: long header. 0-RTT Protected. CH. LRU hit.",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder =
         PacketBuilder::newPacket()
             .Eth("0x1", "0x2")
             .IPv4("192.168.1.42", "10.200.1.5")
             .UDP(31337, 443)
             .QUIC0RTT()
             .destConnId({0x43, 0xFF, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})
             .version(QUIC_V1_WIRE_FORMAT)
             .packetNumber(0x11, 1) // Packet number 0x11 (1 byte)
             .data("\x01quic data") // Data after packet number
             .done(),
     .expectedOutputPacketBuilder =
         PacketBuilder::newPacket()
             .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
             .IPv4("172.16.104.80", "10.0.0.2", 64, 0, 0) // Outer IPv4
             // encapsulation
             .IPv4("192.168.1.42", "10.200.1.5") // Inner IPv4
             .UDP(31337, 443)
             .QUIC0RTT()
             .destConnId({0x43, 0xFF, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})
             .version(QUIC_V1_WIRE_FORMAT)
             .packetNumber(0x11, 1) // Packet number 0x11 (1 byte)
             .data("\x01quic data") // Data after packet number
             .done()},
    // 26
    {.description =
         "QUIC: long header. Handshake. v4 vip v6 real. Conn Id V1 based. server id is 1024 mapped to fc00::1.",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder =
         PacketBuilder::newPacket()
             .Eth("0x1", "0x2")
             .IPv4("192.168.1.42", "10.200.1.5")
             .UDP(31337, 443)
             .QUICHandshake()
             .destConnId({0x41, 0x00, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00})
             .version(QUIC_V1_WIRE_FORMAT)
             .packetNumber(0x11, 1)
             .data("\x01quic data\x00@") // Data after packet number
             .done(),
     .expectedOutputPacketBuilder =
         PacketBuilder::newPacket()
             .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
             .IPv6("100::bac1:12a", "fc00::1") // Outer IPv6 encapsulation
             .IPv4("192.168.1.42", "10.200.1.5") // Inner IPv4
             .UDP(31337, 443)
             .QUICHandshake()
             .destConnId({0x41, 0x00, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00})
             .version(QUIC_V1_WIRE_FORMAT)
             .packetNumber(0x11, 1)
             .data("\x01quic data\x00@") // Data after packet number
             .done()},
    // 27
    {.description =
         "QUIC: long header. Retry. v4 vip v6 real. Conn Id V1 based. server id is 1024 mapped to fc00::1.",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder =
         PacketBuilder::newPacket()
             .Eth("0x1", "0x2")
             .IPv4("192.168.1.42", "10.200.1.5")
             .UDP(31337, 443)
             .QUICRetry()
             .destConnId({0x41, 0x00, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00})
             .version(QUIC_V1_WIRE_FORMAT)
             .data("\x01\x11\x01quic data\x00@")
             .done(),
     .expectedOutputPacketBuilder =
         PacketBuilder::newPacket()
             .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
             .IPv6("100::bac1:12a", "fc00::1") // Outer IPv6 encapsulation
             .IPv4("192.168.1.42", "10.200.1.5") // Inner IPv4
             .UDP(31337, 443)
             .QUICRetry()
             .destConnId({0x41, 0x00, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00})
             .version(QUIC_V1_WIRE_FORMAT)
             .data("\x01\x11\x01quic data\x00@")
             .done()},
    // 28
    {.description =
         "QUIC: long header. client initial. v6 vip v6 real. LRU miss",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder =
         PacketBuilder::newPacket()
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
     .expectedOutputPacketBuilder =
         PacketBuilder::newPacket()
             .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
             .IPv6("100::7a69:42", "fc00::1") // Outer IPv6 encapsulation
             .IPv6("fc00:2::42", "fc00:1::2") // Inner IPv6
             .UDP(31337, 443)
             .QUICInitial()
             .destConnId({0x44, 0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00})
             .version(QUIC_V1_WIRE_FORMAT)
             .token({0x11})
             .packetNumber(0x11, 1)
             .data("\x01quic data\x00@")
             .done()},
    // 29
    {.description = "QUIC: short header. No connection id. LRU hit",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = PacketBuilder::newPacket()
                               .Eth("0x1", "0x2")
                               .IPv4("192.168.1.42", "10.200.1.5")
                               .UDP(31337, 443)
                               .payload(std::string(
                                   "\x00",
                                   1)), // QUIC short header with no connection
     // ID (explicit 1-byte payload)
     .expectedOutputPacketBuilder =
         PacketBuilder::newPacket()
             .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
             .IPv6("100::bac1:12a", "fc00::1") // Outer IPv6 encapsulation
             .IPv4("192.168.1.42", "10.200.1.5") // Inner IPv4
             .UDP(31337, 443)
             .payload(std::string("\x00", 1))},
    // 30
    {.description = "QUIC: short header w/ connection id",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder =
         PacketBuilder::newPacket()
             .Eth("0x1", "0x2")
             .IPv4("192.168.1.42", "10.200.1.5")
             .UDP(31337, 443)
             .QUICShortHeader()
             .destConnId({0x41, 0x00, 0x83, 0x04, 0x05, 0x06, 0x07, 0x00})
             .cidVersion(QUICHeader::CID_V1)
             .data("@")
             .done(),
     .expectedOutputPacketBuilder =
         PacketBuilder::newPacket()
             .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
             .IPv6("100::bac1:12a", "fc00::2") // Outer IPv6 encapsulation
             .IPv4("192.168.1.42", "10.200.1.5") // Inner IPv4
             .UDP(31337, 443)
             .QUICShortHeader()
             .destConnId({0x41, 0x00, 0x83, 0x04, 0x05, 0x06, 0x07, 0x00})
             .cidVersion(QUICHeader::CID_V1)
             .data("@")
             .done()},
    // 31
    {.description =
         "QUIC: short header w/ connection id 1092 but non-existing mapping. LRU hit",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder =
         PacketBuilder::newPacket()
             .Eth("0x1", "0x2")
             .IPv4("192.168.1.42", "10.200.1.5")
             .UDP(31337, 443)
             .QUICShortHeader()
             .destConnId({0x41, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
             .cidVersion(QUICHeader::CID_V1)
             .data("@")
             .done(),
     .expectedOutputPacketBuilder =
         PacketBuilder::newPacket()
             .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
             .IPv6("100::bac1:12a", "fc00::2") // Outer IPv6 encapsulation
             .IPv4("192.168.1.42", "10.200.1.5") // Inner IPv4
             .UDP(31337, 443)
             .QUICShortHeader()
             .destConnId({0x41, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
             .cidVersion(QUICHeader::CID_V1)
             .data("@")
             .done()},
    // 32
    {.description = "QUIC: short header w/ conn id. host id = 0. LRU hit",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder =
         PacketBuilder::newPacket()
             .Eth("0x1", "0x2")
             .IPv4("192.168.1.42", "10.200.1.5")
             .UDP(31337, 443)
             .QUICShortHeader()
             .destConnId({0x40, 0x00, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00})
             .cidVersion(QUICHeader::CID_V1)
             .data("@")
             .done(),
     .expectedOutputPacketBuilder =
         PacketBuilder::newPacket()
             .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
             .IPv6("100::bac1:12a", "fc00::2") // Outer IPv6 encapsulation
             .IPv4("192.168.1.42", "10.200.1.5") // Inner IPv4
             .UDP(31337, 443)
             .QUICShortHeader()
             .destConnId({0x40, 0x00, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00})
             .cidVersion(QUICHeader::CID_V1)
             .data("@")
             .done()},
    // 33
    {.description = "UDP: big packet of length 1515. trigger PACKET TOOBIG",
     .expectedReturnValue = "XDP_DROP",
     .inputPacketBuilder =
         PacketBuilder::newPacket()
             .Eth("0x1", "0x2")
             .IPv4("192.168.1.1", "10.200.1.1")
             .UDP(31337, 80)
             .payload(
                 "797883370329577106344738025230573564933167024829388081199648613840181948753884603247773669576367045816906284210962088269452146983146773303572445414493700126379947519594617279357929777570929325860830039096091203526291264864513542906692645769582519710708146806211724766482394164005416688079197391206390291800153547603161357657905347836435363362258350333327968302049102730916469649631532883387397583916004554030850139851376438322245758946060430921264977061015778749816231475574683816838619259807655931220795697682284954906880260632459503382535673347232340672712872085970621009076782437411771791551329842711821074993004777147846777968599066211476974862400025965589871325380269066383201236046194226097412017387088327538130521122420827406683370673844193724595563783044714305297107179416676764561048892835737142761150503744154953946035972924731238539850461448318494496268373100206653235516775716526934632728260602480974769255349523718921695003303256908780943055708356809531994363765861758421672525747311758888535567205741264950159702489816356213175465739855866153012852319837133169609108399049569392787059007320348485587140225630001806623997261443135380559061473232316323280548661452809842971089915994143899853429115004941958629228897469173695836986909717605784471995226579683503001346229696994592477055771496459331881518232837513385658290651179198213387140762445500281711027571185400631194546006855583740597941249698709012834121767342458862311760244799976325978531665537629948602"),
     .expectedOutputPacketBuilder =
         PacketBuilder::newPacket()
             .Eth("0x1", "0x2")
             .IPv4("192.168.1.1", "10.200.1.1")
             .UDP(31337, 80)
             .payload(
                 "797883370329577106344738025230573564933167024829388081199648613840181948753884603247773669576367045816906284210962088269452146983146773303572445414493700126379947519594617279357929777570929325860830039096091203526291264864513542906692645769582519710708146806211724766482394164005416688079197391206390291800153547603161357657905347836435363362258350333327968302049102730916469649631532883387397583916004554030850139851376438322245758946060430921264977061015778749816231475574683816838619259807655931220795697682284954906880260632459503382535673347232340672712872085970621009076782437411771791551329842711821074993004777147846777968599066211476974862400025965589871325380269066383201236046194226097412017387088327538130521122420827406683370673844193724595563783044714305297107179416676764561048892835737142761150503744154953946035972924731238539850461448318494496268373100206653235516775716526934632728260602480974769255349523718921695003303256908780943055708356809531994363765861758421672525747311758888535567205741264950159702489816356213175465739855866153012852319837133169609108399049569392787059007320348485587140225630001806623997261443135380559061473232316323280548661452809842971089915994143899853429115004941958629228897469173695836986909717605784471995226579683503001346229696994592477055771496459331881518232837513385658290651179198213387140762445500281711027571185400631194546006855583740597941249698709012834121767342458862311760244799976325978531665537629948602")},
    // 34
    {.description = "QUIC: short header w/ connection id. CIDv2",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder =
         PacketBuilder::newPacket()
             .Eth("0x1", "0x2")
             .IPv4("192.168.1.42", "10.200.1.5")
             .UDP(31337, 443)
             .QUICShortHeader()
             .destConnId({0x80, 0x03, 0x04, 0x02, 0x05, 0x06, 0x07, 0x00})
             .cidVersion(QUICHeader::CID_V2)
             .data("@")
             .done(),
     .expectedOutputPacketBuilder =
         PacketBuilder::newPacket()
             .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
             .IPv6("100::bac1:12a", "fc00::2") // Outer IPv6 encapsulation
             .IPv4("192.168.1.42", "10.200.1.5") // Inner IPv4
             .UDP(31337, 443)
             .QUICShortHeader()
             .destConnId({0x80, 0x03, 0x04, 0x02, 0x05, 0x06, 0x07, 0x00})
             .cidVersion(QUICHeader::CID_V2)
             .data("@")
             .done()},
    // 35
    {.description =
         "QUIC: short header w/ connection id 197700 but non-existing mapping. CIDv2. LRU hit.",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder =
         PacketBuilder::newPacket()
             .Eth("0x1", "0x2")
             .IPv4("192.168.1.42", "10.200.1.5")
             .UDP(31337, 443)
             .QUICShortHeader()
             .destConnId({0x80, 0x03, 0x04, 0x44, 0x00, 0x00, 0x00, 0x00})
             .cidVersion(QUICHeader::CID_V2)
             .data("@")
             .done(),
     .expectedOutputPacketBuilder =
         PacketBuilder::newPacket()
             .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
             .IPv6("100::bac1:12a", "fc00::2") // Outer IPv6 encapsulation
             .IPv4("192.168.1.42", "10.200.1.5") // Inner IPv4
             .UDP(31337, 443)
             .QUICShortHeader()
             .destConnId({0x80, 0x03, 0x04, 0x44, 0x00, 0x00, 0x00, 0x00})
             .cidVersion(QUICHeader::CID_V2)
             .data("@")
             .done()},
    // 36
    {.description = "Packet to udp vip with udp flow migration enabled",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder =
         PacketBuilder::newPacket()
             .Eth("0x1", "0x2")
             .IPv4("192.168.1.42", "10.200.1.6")
             .UDP(31337, 80)
             .QUICShortHeader()
             .destConnId({0x80, 0x03, 0x04, 0x44, 0x00, 0x00, 0x00, 0x00})
             .cidVersion(QUICHeader::CID_V2)
             .data("@")
             .done(),
     .expectedOutputPacketBuilder =
         PacketBuilder::newPacket()
             .Eth("02:00:00:00:00:00", "00:00:de:ad:be:af")
             .IPv4("172.16.104.80", "10.0.0.3", 64, 0, 0) // Outer IPv4
                                                          // (IPIP)
             .IPv4("192.168.1.42", "10.200.1.6") // Inner IPv4
             .UDP(31337, 80)
             .QUICShortHeader()
             .destConnId({0x80, 0x03, 0x04, 0x44, 0x00, 0x00, 0x00, 0x00})
             .cidVersion(QUICHeader::CID_V2)
             .data("@")
             .done()},
};

} // namespace testing
} // namespace katran
