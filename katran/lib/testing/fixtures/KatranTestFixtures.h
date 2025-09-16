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
                               .IPv4("192.168.1.1","10.200.1.1",64,0,1,PacketBuilder::IP_FLAG_MF)
                               .TCP(31337, 80, 0, 0, 8192, TH_ACK)
                               .payload("katran test pkt"),
     .expectedOutputPacketBuilder = PacketBuilder::newPacket()
                                        .Eth("0x1", "0x2")
                                        .IPv4("192.168.1.1","10.200.1.1",64,0,1,PacketBuilder::IP_FLAG_MF)
                                        .TCP(31337, 80, 0, 0, 8192, TH_ACK)
                                        .payload("katran test pkt")},
    // 14
    {.description = "drop of IPv6 fragmented packet",
     .expectedReturnValue = "XDP_DROP",
     .inputPacketBuilder = PacketBuilder::newPacket()
                               .Eth("0x1", "0x2")
                               .IPv6("fc00:2::1","fc00:1::1",64,0,0,PacketBuilder::IPV6_NH_FRAGMENT)
                               .TCP(31337, 80, 0, 0, 8192, TH_ACK)
                               .payload("katran test pkt"),
     .expectedOutputPacketBuilder = PacketBuilder::newPacket()
                                        .Eth("0x1", "0x2")
                                        .IPv6("fc00:2::1","fc00:1::1",64,0,0,PacketBuilder::IPV6_NH_FRAGMENT)
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
      //18
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.1")/TCP(sport=31337, dport=80, flags="A")/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGrU7AqAEBCsgBAXppAFAAAAAAAAAAAFAQIAAn5AAAa2F0cmFuIHRlc3QgcGt0",
    .description = "LRU hit",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAACABFAABLAAAAAEAEXCGsEGh7CgAAA0UAADcAAQAAQAatTsCoAQEKyAEBemkAUAAAAAAAAAAAUBAgACfkAABrYXRyYW4gdGVzdCBwa3Q="
  },
  //19
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.4")/TCP(sport=31337, dport=42, flags="A")/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGrUvAqAEBCsgBBHppACoAAAAAAAAAAFAQIAAoBwAAa2F0cmFuIHRlc3QgcGt0",
    .description = "packet #1 dst port hashing only",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAACABFAABLAAAAAEAEWyOsEGl6CgAAAkUAADcAAQAAQAatS8CoAQEKyAEEemkAKgAAAAAAAAAAUBAgACgHAABrYXRyYW4gdGVzdCBwa3Q="
  },
  //20
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.100", dst="10.200.1.4")/TCP(sport=1337, dport=42, flags="A")/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGrOjAqAFkCsgBBAU5ACoAAAAAAAAAAFAQIACc1AAAa2F0cmFuIHRlc3QgcGt0",
    .description = "packet #2 dst port hashing only",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAACABFAABLAAAAAEAEi5isEDkFCgAAAkUAADcAAQAAQAas6MCoAWQKyAEEBTkAKgAAAAAAAAAAUBAgAJzUAABrYXRyYW4gdGVzdCBwa3Q="
  },
  //21
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.4")/TCP(sport=31337, dport=42, flags="A")/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAACABFAAA/AAEAAEAEvZesEAEBrBBkAUUAACsAAQAAQBGtT8CoAQEKyAEBemkAUAAXl95rYXRyYW4gdGVzdCBwa3Q=",
    .description = "ipinip packet",
    .expectedReturnValue = "XDP_PASS",
    .expectedOutputPacket = "AgAAAAAAAQAAAAAACABFAAA/AAEAAEAEvZesEAEBrBBkAUUAACsAAQAAQBGtT8CoAQEKyAEBemkAUAAXl95rYXRyYW4gdGVzdCBwa3Q="
  },
  //22
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="100::1", dst="100::2")/IPv6(src="fc00:2::1", dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAAEspQAEAAAAAAAAAAAAAAAAAAAEBAAAAAAAAAAAAAAAAAAACYAAAAAAjBkD8AAACAAAAAAAAAAAAAAAB/AAAAQAAAAAAAAAAAAAAAXppAFAAAAAAAAAAAFAQIAD9TwAAa2F0cmFuIHRlc3QgcGt0",
    .description = "ipv6inipv6 packet",
    .expectedReturnValue = "XDP_PASS",
    .expectedOutputPacket = "AgAAAAAAAQAAAAAAht1gAAAAAEspQAEAAAAAAAAAAAAAAAAAAAEBAAAAAAAAAAAAAAAAAAACYAAAAAAjBkD8AAACAAAAAAAAAAAAAAAB/AAAAQAAAAAAAAAAAAAAAXppAFAAAAAAAAAAAFAQIAD9TwAAa2F0cmFuIHRlc3QgcGt0"
  },
  //23
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="100::1", dst="100::2")/IP(src="192.168.1.1", dst="10.200.1.1")/UDP(sport=31337, dport=80)/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAACsEQAEAAAAAAAAAAAAAAAAAAAEBAAAAAAAAAAAAAAAAAAACRQAAKwABAABAEa1PwKgBAQrIAQF6aQBQABeX3mthdHJhbiB0ZXN0IHBrdA==",
    .description = "ipv4inipv6 packet",
    .expectedReturnValue = "XDP_PASS",
    .expectedOutputPacket = "AgAAAAAAAQAAAAAAht1gAAAAACsEQAEAAAAAAAAAAAAAAAAAAAEBAAAAAAAAAAAAAAAAAAACRQAAKwABAABAEa1PwKgBAQrIAQF6aQBQABeX3mthdHJhbiB0ZXN0IHBrdA=="
  },
  //24
  {
    // Ether(src="0x1", dst="0x2")/IP(src="192.168.1.42", dst="10.200.1.5")/UDP(sport=31337, dport=443)/'\xcf\xfa\xce\xb0\x01\x08\x41\x02\x03\x04\x05\x06\x07\x00\x00\x01\x11\x01quic data\x00@'
    .inputPacket = "AgAAAAAAAQAAAAAACABFAAA5AAEAAEARrRTAqAEqCsgBBXppAbsAJbdsz/rOsAEIQQIDBAUGBwAAAREBcXVpYyBkYXRhAEA=",
    .description = "QUIC: long header. Client Initial type. LRU miss",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAACABFAABNAAAAAEAEXEusEGhQCgAAAkUAADkAAQAAQBGtFMCoASoKyAEFemkBuwAlt2zP+s6wAQhBAgMEBQYHAAABEQFxdWljIGRhdGEAQA=="
  },
  //25
  {
    // Ether(src="0x1", dst="0x2")/IP(src="192.168.1.42", dst="10.200.1.5")/UDP(sport=31337, dport=443)/'\xdf\xfa\xce\xb0\x01\x08\x43\xFF\x33\x44\x55\x66\x77\x88\x00\x01\x11\x01quic data\x00@'
    .inputPacket = "AgAAAAAAAQAAAAAACABFAAA5AAEAAEARrRTAqAEqCsgBBXppAbsAJbNG3/rOsAEIQ/8zRFVmd4gAAREBcXVpYyBkYXRhAEA=",
    .description = "QUIC: long header. 0-RTT Protected. CH. LRU hit.",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAACABFAABNAAAAAEAEXEusEGhQCgAAAkUAADkAAQAAQBGtFMCoASoKyAEFemkBuwAls0bf+s6wAQhD/zNEVWZ3iAABEQFxdWljIGRhdGEAQA=="
  },
  //26
  {
    // Ether(src="0x1", dst="0x2")/IP(src="192.168.1.42", dst="10.200.1.5")/UDP(sport=31337, dport=443)/'\xef\xfa\xce\xb0\x01\x08\x41\x00\x03\x04\x05\x06\x07\x00\x00\x01\x11\x01quic data\x00@'
    .inputPacket = "AgAAAAAAAQAAAAAACABFAAA5AAEAAEARrRTAqAEqCsgBBXppAbsAJZRt7/rOsAEIQQADBAUGBwAAAREBcXVpYyBkYXRhAEA=",
    .description = "QUIC: long header. Handshake. v4 vip v6 real. Conn Id V1 based. server id is 1024 mapped to fc00::1.",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAADkEQAEAAAAAAAAAAAAAALrBASr8AAAAAAAAAAAAAAAAAAABRQAAOQABAABAEa0UwKgBKgrIAQV6aQG7ACWUbe/6zrABCEEAAwQFBgcAAAERAXF1aWMgZGF0YQBA"
  },
  //27
  {
    // Ether(src="0x1", dst="0x2")/IP(src="192.168.1.42", dst="10.200.1.5")/UDP(sport=31337, dport=443)/'\xff\xfa\xce\xb0\x01\x08\x41\x00\x03\x04\x05\x06\x07\x00\x00\x01\x11\x01quic data\x00@'
    .inputPacket = "AgAAAAAAAQAAAAAACABFAAA5AAEAAEARrRTAqAEqCsgBBXppAbsAJYRt//rOsAEIQQADBAUGBwAAAREBcXVpYyBkYXRhAEA=",
    .description = "QUIC: long header. Retry. v4 vip v6 real. Conn Id V1 based. server id is 1024 mapped to fc00::1.",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAADkEQAEAAAAAAAAAAAAAALrBASr8AAAAAAAAAAAAAAAAAAABRQAAOQABAABAEa0UwKgBKgrIAQV6aQG7ACWEbf/6zrABCEEAAwQFBgcAAAERAXF1aWMgZGF0YQBA"
  },
  //28
  {
    // Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::42", dst="fc00:1::2")/UDP(sport=31337, dport=443)/'\xcf\xfa\xce\xb0\x01\x08\x44\x01\x03\x04\x05\x06\x07\x00\x00\x01\x11\x01quic data\x00@'
    .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAACURQPwAAAIAAAAAAAAAAAAAAEL8AAABAAAAAAAAAAAAAAACemkBuwAlicTP+s6wAQhEAQMEBQYHAAABEQFxdWljIGRhdGEAQA==",
    .description = "QUIC: long header. client initial. v6 vip v6 real. LRU miss",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAE0pQAEAAAAAAAAAAAAAAHppAEL8AAAAAAAAAAAAAAAAAAABYAAAAAAlEUD8AAACAAAAAAAAAAAAAABC/AAAAQAAAAAAAAAAAAAAAnppAbsAJYnEz/rOsAEIRAEDBAUGBwAAAREBcXVpYyBkYXRhAEA="
  },
  //29
  {
    // Ether(src="0x1", dst="0x2")/IP(src="192.168.1.42", dst="10.200.1.5")/UDP(sport=31337, dport=443)/'\x00'
    .inputPacket = "AgAAAAAAAQAAAAAACABFAAAdAAEAAEARrTDAqAEqCsgBBXppAbsACbYYAA==",
    .description = "QUIC: short header. No connection id. LRU hit",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAB0EQAEAAAAAAAAAAAAAALrBASr8AAAAAAAAAAAAAAAAAAABRQAAHQABAABAEa0wwKgBKgrIAQV6aQG7AAm2GAA="
  },
  //30
  {
    // Ether(src="0x1", dst="0x2")/IP(src="192.168.1.42", dst="10.200.1.5")/UDP(sport=31337, dport=443)/'\x00\x41\x00\x83\x04\x05\x06\x07\x00@'
    .inputPacket = "AgAAAAAAAQAAAAAACABFAAAmAAEAAEARrSfAqAEqCsgBBXppAbsAEqr2AEEAgwQFBgcAQA==",
    .description = "QUIC: short header w/ connection id",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAACYEQAEAAAAAAAAAAAAAALrBASr8AAAAAAAAAAAAAAAAAAACRQAAJgABAABAEa0nwKgBKgrIAQV6aQG7ABKq9gBBAIMEBQYHAEA="
  },
  //31
  {
    // Ether(src="0x1", dst="0x2")/IP(src="192.168.1.42", dst="10.200.1.5")/UDP(sport=31337, dport=443)/'\x00\x41\x11\x00\x00\x00\x00\x00\x00@'
    .inputPacket = "AgAAAAAAAQAAAAAACABFAAAmAAEAAEARrSfAqAEqCsgBBXppAbsAEqSFAEERAAAAAAAAQA==",
    .description = "QUIC: short header w/ connection id 1092 but non-existing mapping. LRU hit",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAACYEQAEAAAAAAAAAAAAAALrBASr8AAAAAAAAAAAAAAAAAAACRQAAJgABAABAEa0nwKgBKgrIAQV6aQG7ABKkhQBBEQAAAAAAAEA="
  },
  //32
  {
    // Ether(src="0x1", dst="0x2")/IP(src="192.168.1.42", dst="10.200.1.5")/UDP(sport=31337, dport=443)/'\x00\x40\x00\x03\x04\x05\x06\x07\x00@'
    .inputPacket = "AgAAAAAAAQAAAAAACABFAAAmAAEAAEARrSfAqAEqCsgBBXppAbsAEqt3AEAAAwQFBgcAQA==",
    .description = "QUIC: short header w/ conn id. host id = 0. LRU hit",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAACYEQAEAAAAAAAAAAAAAALrBASr8AAAAAAAAAAAAAAAAAAACRQAAJgABAABAEa0nwKgBKgrIAQV6aQG7ABKrdwBAAAMEBQYHAEA="
  },
  //33
  {
    // Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.1")/UDP(sport=31337, dport=80)/<random payload of length 1473, forming a packet of length 1515>
    .inputPacket = "AgAAAAAAAQAAAAAACABFAAXdAAEAAEARp53AqAEBCsgBAXppAFAFybmiNzk3ODgzMzcwMzI5NTc3MTA2MzQ0NzM4MDI1MjMwNTczNTY0OTMzMTY3MDI0ODI5Mzg4MDgxMTk5NjQ4NjEzODQwMTgxOTQ4NzUzODg0NjAzMjQ3NzczNjY5NTc2MzY3MDQ1ODE2OTA2Mjg0MjEwOTYyMDg4MjY5NDUyMTQ2OTgzMTQ2NzczMzAzNTcyNDQ1NDE0NDkzNzAwMTI2Mzc5OTQ3NTE5NTk0NjE3Mjc5MzU3OTI5Nzc3NTcwOTI5MzI1ODYwODMwMDM5MDk2MDkxMjAzNTI2MjkxMjY0ODY0NTEzNTQyOTA2NjkyNjQ1NzY5NTgyNTE5NzEwNzA4MTQ2ODA2MjExNzI0NzY2NDgyMzk0MTY0MDA1NDE2Njg4MDc5MTk3MzkxMjA2MzkwMjkxODAwMTUzNTQ3NjAzMTYxMzU3NjU3OTA1MzQ3ODM2NDM1MzYzMzYyMjU4MzUwMzMzMzI3OTY4MzAyMDQ5MTAyNzMwOTE2NDY5NjQ5NjMxNTMyODgzMzg3Mzk3NTgzOTE2MDA0NTU0MDMwODUwMTM5ODUxMzc2NDM4MzIyMjQ1NzU4OTQ2MDYwNDMwOTIxMjY0OTc3MDYxMDE1Nzc4NzQ5ODE2MjMxNDc1NTc0NjgzODE2ODM4NjE5MjU5ODA3NjU1OTMxMjIwNzk1Njk3NjgyMjg0OTU0OTA2ODgwMjYwNjMyNDU5NTAzMzgyNTM1NjczMzQ3MjMyMzQwNjcyNzEyODcyMDg1OTcwNjIxMDA5MDc2NzgyNDM3NDExNzcxNzkxNTUxMzI5ODQyNzExODIxMDc0OTkzMDA0Nzc3MTQ3ODQ2Nzc3OTY4NTk5MDY2MjExNDc2OTc0ODYyNDAwMDI1OTY1NTg5ODcxMzI1MzgwMjY5MDY2MzgzMjAxMjM2MDQ2MTk0MjI2MDk3NDEyMDE3Mzg3MDg4MzI3NTM4MTMwNTIxMTIyNDIwODI3NDA2NjgzMzcwNjczODQ0MTkzNzI0NTk1NTYzNzgzMDQ0NzE0MzA1Mjk3MTA3MTc5NDE2Njc2NzY0NTYxMDQ4ODkyODM1NzM3MTQyNzYxMTUwNTAzNzQ0MTU0OTUzOTQ2MDM1OTcyOTI0NzMxMjM4NTM5ODUwNDYxNDQ4MzE4NDk0NDk2MjY4MzczMTAwMjA2NjUzMjM1NTE2Nzc1NzE2NTI2OTM0NjMyNzI4MjYwNjAyNDgwOTc0NzY5MjU1MzQ5NTIzNzE4OTIxNjk1MDAzMzAzMjU2OTA4NzgwOTQzMDU1NzA4MzU2ODA5NTMxOTk0MzYzNzY1ODYxNzU4NDIxNjcyNTI1NzQ3MzExNzU4ODg4NTM1NTY3MjA1NzQxMjY0OTUwMTU5NzAyNDg5ODE2MzU2MjEzMTc1NDY1NzM5ODU1ODY2MTUzMDEyODUyMzE5ODM3MTMzMTY5NjA5MTA4Mzk5MDQ5NTY5MzkyNzg3MDU5MDA3MzIwMzQ4NDg1NTg3MTQwMjI1NjMwMDAxODA2NjIzOTk3MjYxNDQzMTM1MzgwNTU5MDYxNDczMjMyMzE2MzIzMjgwNTQ4NjYxNDUyODA5ODQyOTcxMDg5OTE1OTk0MTQzODk5ODUzNDI5MTE1MDA0OTQxOTU4NjI5MjI4ODk3NDY5MTczNjk1ODM2OTg2OTA5NzE3NjA1Nzg0NDcxOTk1MjI2NTc5NjgzNTAzMDAxMzQ2MjI5Njk2OTk0NTkyNDc3MDU1NzcxNDk2NDU5MzMxODgxNTE4MjMyODM3NTEzMzg1NjU4MjkwNjUxMTc5MTk4MjEzMzg3MTQwNzYyNDQ1NTAwMjgxNzExMDI3NTcxMTg1NDAwNjMxMTk0NTQ2MDA2ODU1NTgzNzQwNTk3OTQxMjQ5Njk4NzA5MDEyODM0MTIxNzY3MzQyNDU4ODYyMzExNzYwMjQ0Nzk5OTc2MzI1OTc4NTMxNjY1NTM3NjI5OTQ4NjAy",
    .description = "UDP: big packet of length 1515. trigger PACKET TOOBIG",
    .expectedReturnValue = "XDP_DROP",
    .expectedOutputPacket = "AgAAAAAAAQAAAAAACABFAAXdAAEAAEARp53AqAEBCsgBAXppAFAFybmiNzk3ODgzMzcwMzI5NTc3MTA2MzQ0NzM4MDI1MjMwNTczNTY0OTMzMTY3MDI0ODI5Mzg4MDgxMTk5NjQ4NjEzODQwMTgxOTQ4NzUzODg0NjAzMjQ3NzczNjY5NTc2MzY3MDQ1ODE2OTA2Mjg0MjEwOTYyMDg4MjY5NDUyMTQ2OTgzMTQ2NzczMzAzNTcyNDQ1NDE0NDkzNzAwMTI2Mzc5OTQ3NTE5NTk0NjE3Mjc5MzU3OTI5Nzc3NTcwOTI5MzI1ODYwODMwMDM5MDk2MDkxMjAzNTI2MjkxMjY0ODY0NTEzNTQyOTA2NjkyNjQ1NzY5NTgyNTE5NzEwNzA4MTQ2ODA2MjExNzI0NzY2NDgyMzk0MTY0MDA1NDE2Njg4MDc5MTk3MzkxMjA2MzkwMjkxODAwMTUzNTQ3NjAzMTYxMzU3NjU3OTA1MzQ3ODM2NDM1MzYzMzYyMjU4MzUwMzMzMzI3OTY4MzAyMDQ5MTAyNzMwOTE2NDY5NjQ5NjMxNTMyODgzMzg3Mzk3NTgzOTE2MDA0NTU0MDMwODUwMTM5ODUxMzc2NDM4MzIyMjQ1NzU4OTQ2MDYwNDMwOTIxMjY0OTc3MDYxMDE1Nzc4NzQ5ODE2MjMxNDc1NTc0NjgzODE2ODM4NjE5MjU5ODA3NjU1OTMxMjIwNzk1Njk3NjgyMjg0OTU0OTA2ODgwMjYwNjMyNDU5NTAzMzgyNTM1NjczMzQ3MjMyMzQwNjcyNzEyODcyMDg1OTcwNjIxMDA5MDc2NzgyNDM3NDExNzcxNzkxNTUxMzI5ODQyNzExODIxMDc0OTkzMDA0Nzc3MTQ3ODQ2Nzc3OTY4NTk5MDY2MjExNDc2OTc0ODYyNDAwMDI1OTY1NTg5ODcxMzI1MzgwMjY5MDY2MzgzMjAxMjM2MDQ2MTk0MjI2MDk3NDEyMDE3Mzg3MDg4MzI3NTM4MTMwNTIxMTIyNDIwODI3NDA2NjgzMzcwNjczODQ0MTkzNzI0NTk1NTYzNzgzMDQ0NzE0MzA1Mjk3MTA3MTc5NDE2Njc2NzY0NTYxMDQ4ODkyODM1NzM3MTQyNzYxMTUwNTAzNzQ0MTU0OTUzOTQ2MDM1OTcyOTI0NzMxMjM4NTM5ODUwNDYxNDQ4MzE4NDk0NDk2MjY4MzczMTAwMjA2NjUzMjM1NTE2Nzc1NzE2NTI2OTM0NjMyNzI4MjYwNjAyNDgwOTc0NzY5MjU1MzQ5NTIzNzE4OTIxNjk1MDAzMzAzMjU2OTA4NzgwOTQzMDU1NzA4MzU2ODA5NTMxOTk0MzYzNzY1ODYxNzU4NDIxNjcyNTI1NzQ3MzExNzU4ODg4NTM1NTY3MjA1NzQxMjY0OTUwMTU5NzAyNDg5ODE2MzU2MjEzMTc1NDY1NzM5ODU1ODY2MTUzMDEyODUyMzE5ODM3MTMzMTY5NjA5MTA4Mzk5MDQ5NTY5MzkyNzg3MDU5MDA3MzIwMzQ4NDg1NTg3MTQwMjI1NjMwMDAxODA2NjIzOTk3MjYxNDQzMTM1MzgwNTU5MDYxNDczMjMyMzE2MzIzMjgwNTQ4NjYxNDUyODA5ODQyOTcxMDg5OTE1OTk0MTQzODk5ODUzNDI5MTE1MDA0OTQxOTU4NjI5MjI4ODk3NDY5MTczNjk1ODM2OTg2OTA5NzE3NjA1Nzg0NDcxOTk1MjI2NTc5NjgzNTAzMDAxMzQ2MjI5Njk2OTk0NTkyNDc3MDU1NzcxNDk2NDU5MzMxODgxNTE4MjMyODM3NTEzMzg1NjU4MjkwNjUxMTc5MTk4MjEzMzg3MTQwNzYyNDQ1NTAwMjgxNzExMDI3NTcxMTg1NDAwNjMxMTk0NTQ2MDA2ODU1NTgzNzQwNTk3OTQxMjQ5Njk4NzA5MDEyODM0MTIxNzY3MzQyNDU4ODYyMzExNzYwMjQ0Nzk5OTc2MzI1OTc4NTMxNjY1NTM3NjI5OTQ4NjAy"
  },
  //34
  {
    // Ether(src="0x1", dst="0x2")/IP(src="192.168.1.42", dst="10.200.1.5")/UDP(sport=31337, dport=443)/b'\x00\x80\x03\x04\x02\x05\x06\x07\x00@'
    .inputPacket = "AgAAAAAAAQAAAAAACABFAAAmAAEAAEARrSfAqAEqCsgBBXppAbsAEqo2AIADBAIFBgcAQA==",
    .description = "QUIC: short header w/ connection id. CIDv2",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAACYEQAEAAAAAAAAAAAAAALrBASr8AAAAAAAAAAAAAAAAAAACRQAAJgABAABAEa0nwKgBKgrIAQV6aQG7ABKqNgCAAwQCBQYHAEA="
  },
  //35
  {
    // Ether(src="0x1", dst="0x2")/IP(src="192.168.1.42", dst="10.200.1.5")/UDP(sport=31337, dport=443)/b'\x00\x80\x03\x04\x44\x00\x00\x00\x00@'
    .inputPacket = "AgAAAAAAAQAAAAAACABFAAAmAAEAAEARrSfAqAEqCsgBBXppAbsAEm5CAIADBEQAAAAAQA==",
    .description = "QUIC: short header w/ connection id 197700 but non-existing mapping. CIDv2. LRU hit.",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAACYEQAEAAAAAAAAAAAAAALrBASr8AAAAAAAAAAAAAAAAAAACRQAAJgABAABAEa0nwKgBKgrIAQV6aQG7ABJuQgCAAwREAAAAAEA="
  },
  //36
  {
    // Ether(src="0x1", dst="0x2")/IP(src="192.168.1.42", dst="10.200.1.6")/UDP(sport=31337, dport=80)/b'\x00\x80\x03\x04\x44\x00\x00\x00\x00@'
    .inputPacket = "AgAAAAAAAQAAAAAACABFAAAmAAEAAEARrSbAqAEqCsgBBnppAFAAEm+sAIADBEQAAAAAQA==",
    .description = "Packet to udp vip with udp flow migration enabled",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAACABFAAA6AAAAAEAEXF2sEGhQCgAAA0UAACYAAQAAQBGtJsCoASoKyAEGemkAUAASb6wAgAMERAAAAABA"
  },
};

} // namespace testing
} // namespace katran
