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
#include <utility>
#include <vector>
#include "katran/lib/testing/PacketAttributes.h"

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
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1",
     // dst="10.200.1.1")/UDP(sport=31337, dport=80)/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAACABFAAArAAEAAEARrU/AqAEBCsgBAXppAFAAF5fea2F0cmFuIHRlc3QgcGt0",
     .description = "packet to UDP based v4 VIP (and v4 real)",
     .expectedReturnValue = "XDP_TX",
     .expectedOutputPacket = "AADerb6vAgAAAAAACABFAABHAAAAAEARWX8KAA0lCgAAA2h7Jp4AMxziRQAAKwABAABAEa1PwKgBAQrIAQF6aQBQABeX3mthdHJhbiB0ZXN0IHBrdA=="
    },
    // 2
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1",
     // dst="10.200.1.1")/TCP(sport=31337, dport=80, flags="A")/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGrU7AqAEBCsgBAXppAFAAAAAAAAAAAFAQIAAn5AAAa2F0cmFuIHRlc3QgcGt0",
     .description = "packet to TCP based v4 VIP (and v4 real)",
     .expectedReturnValue = "XDP_TX",
     .expectedOutputPacket = "AADerb6vAgAAAAAACABFAABTAAAAAEARWXMKAA0lCgAAA2h7Jp4APxzLRQAANwABAABABq1OwKgBAQrIAQF6aQBQAAAAAAAAAABQECAAJ+QAAGthdHJhbiB0ZXN0IHBrdA=="
    },
    // 3
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1",
     // dst="10.200.1.2")/TCP(sport=31337, dport=42, flags="A")/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGrU3AqAEBCsgBAnppACoAAAAAAAAAAFAQIAAoCQAAa2F0cmFuIHRlc3QgcGt0",
     .description = "packet to TCP based v4 VIP (and v4 real; any dst ports).",
     .expectedReturnValue = "XDP_TX",
     .expectedOutputPacket = "AADerb6vAgAAAAAACABFAABTAAAAAEARWXQKAA0lCgAAAmh7Jp4APxzNRQAANwABAABABq1NwKgBAQrIAQJ6aQAqAAAAAAAAAABQECAAKAkAAGthdHJhbiB0ZXN0IHBrdA=="
    },
    // 4
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1",
     // dst="10.200.1.3")/TCP(sport=31337, dport=80, flags="A")/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGrUzAqAEBCsgBA3ppAFAAAAAAAAAAAFAQIAAn4gAAa2F0cmFuIHRlc3QgcGt0",
     .description = "packet to TCP based v4 VIP (and v6 real)",
     .expectedReturnValue = "XDP_TX",
     .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAD8RQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAABe2gmngA//MZFAAA3AAEAAEAGrUzAqAEBCsgBA3ppAFAAAAAAAAAAAFAQIAAn4gAAa2F0cmFuIHRlc3QgcGt0"
    },
    // 5
    {// Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1",
     // dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAACMGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1PAABrYXRyYW4gdGVzdCBwa3Q=",
     .description = "packet to TCP based v6 VIP (and v6 real)",
     .expectedReturnValue = "XDP_TX",
     .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAFMRQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAADemkmngBTycNgAAAAACMGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1PAABrYXRyYW4gdGVzdCBwa3Q="
    },
    // 6
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1",
     // dst="10.200.1.3")/ICMP(type="echo-request")
     .inputPacket = "AgAAAAAAAQAAAAAACABFAAAcAAEAAEABrWzAqAEBCsgBAwgA9/8AAAAA",
     .description = "v4 ICMP echo-request",
     .expectedReturnValue = "XDP_TX",
     .expectedOutputPacket = "AQAAAAAAAgAAAAAACABFAAAcAAEAAEABrWwKyAEDwKgBAQAA//8AAAAA"
    },
    // 7
    {// Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1",
     // dst="fc00:1::1")/ICMPv6EchoRequest()
     .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAAAg6QPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABgACHtgAAAAA=",
     .description = "v6 ICMP echo-request",
     .expectedReturnValue = "XDP_TX",
     .expectedOutputPacket = "AQAAAAAAAgAAAAAAht1gAAAAAAg6QPwAAAEAAAAAAAAAAAAAAAH8AAACAAAAAAAAAAAAAAABgQCGtgAAAAA="
    },
    // 8
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.100.1",
     // dst="10.200.1.1")/ICMP(type="dest-unreach",
     // code="fragmentation-needed")/IP(src="10.200.1.1",
     // dst="192.168.1.1")/TCP(sport=80, dport=31337)/"test katran pkt"
     .inputPacket = "AgAAAAAAAQAAAAAACABFAABTAAEAAEABSjfAqGQBCsgBAQMEypcAAAAARQAANwABAABABq1OCsgBAcCoAQEAUHppAAAAAAAAAABQAiAAGQEAAHRlc3Qga2F0cmFuIHBrdA==",
     .description = "v4 ICMP dest-unreachabe fragmentation-needed",
     .expectedReturnValue = "XDP_TX",
     .expectedOutputPacket = "AADerb6vAgAAAAAACABFAABvAAAAAEARWVcKAA0lCgAAA2h7Jp4AW3+qRQAAUwABAABAAUo3wKhkAQrIAQEDBMqXAAAAAEUAADcAAQAAQAatTgrIAQHAqAEBAFB6aQAAAAAAAAAAUAIgABkBAAB0ZXN0IGthdHJhbiBwa3Q="
    },
    // 9
    {// Ether(src="0x1", dst="0x2")/IPv6(src="fc00:200::1",
     // dst="fc00:1::1")/ICMPv6PacketTooBig()/IPv6(src="fc00:1::1",
     // dst="fc00:2::1")/TCP(sport=80,dport=31337)/"katran test packet"
     .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAAFY6QPwAAgAAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABAgCYMAAABQBgAAAAACYGQPwAAAEAAAAAAAAAAAAAAAH8AAACAAAAAAAAAAAAAAABAFB6aQAAAAAAAAAAUAIgAKiFAABrYXRyYW4gdGVzdCBwYWNrZXQ=",
     .description = "v6 ICMP packet-too-big",
     .expectedReturnValue = "XDP_TX",
     .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAIYRQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAADemkmngCGlZFgAAAAAFY6QPwAAgAAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABAgCYMAAABQBgAAAAACYGQPwAAAEAAAAAAAAAAAAAAAH8AAACAAAAAAAAAAAAAAABAFB6aQAAAAAAAAAAUAIgAKiFAABrYXRyYW4gdGVzdCBwYWNrZXQ="
    },
    // 10
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1",
     // dst="10.200.1.1",ihl=6)/TCP(sport=31337, dport=80,flags="A")/"katran test
     // pkt"
     .inputPacket = "AgAAAAAAAQAAAAAACABGAAA3AAEAAEAGrE7AqAEBCsgBAXppAFAAAAAAAAAAAFAQIAAn5AAAa2F0cmFuIHRlc3QgcGt0",
     .description = "drop of IPv4 packet w/ options",
     .expectedReturnValue = "XDP_DROP",
     .expectedOutputPacket = "AgAAAAAAAQAAAAAACABGAAA3AAEAAEAGrE7AqAEBCsgBAXppAFAAAAAAAAAAAFAQIAAn5AAAa2F0cmFuIHRlc3QgcGt0"
    },
    // 11
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1",
     // dst="10.200.1.1",ihl=5,flags="MF")/TCP(sport=31337,
     // dport=80,flags="A")/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAACABFAAA3AAEgAEAGjU7AqAEBCsgBAXppAFAAAAAAAAAAAFAQIAAn5AAAa2F0cmFuIHRlc3QgcGt0",
     .description = "drop of IPv4 fragmented packet",
     .expectedReturnValue = "XDP_DROP",
     .expectedOutputPacket = "AgAAAAAAAQAAAAAACABFAAA3AAEgAEAGjU7AqAEBCsgBAXppAFAAAAAAAAAAAFAQIAAn5AAAa2F0cmFuIHRlc3QgcGt0"
    },
    // 12
    {// Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1",
     // dst="fc00:1::1",nh=44)/TCP(sport=31337, dport=80,flags="A")/"katran test
     // pkt"
     .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAACMsQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1PAABrYXRyYW4gdGVzdCBwa3Q=",
     .description = "drop of IPv6 fragmented packet",
     .expectedReturnValue = "XDP_DROP",
     .expectedOutputPacket = "AgAAAAAAAQAAAAAAht1gAAAAACMsQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1PAABrYXRyYW4gdGVzdCBwa3Q="
    },
    // 13
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1",
     // dst="10.200.1.1",ihl=5)/TCP(sport=31337, dport=82,flags="A")/"katran test
     // pkt"
     .inputPacket = "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGrU7AqAEBCsgBAXppAFIAAAAAAAAAAFAQIAAn4gAAa2F0cmFuIHRlc3QgcGt0",
     .description = "pass of v4 packet with dst not equal to any configured VIP",
     .expectedReturnValue = "XDP_PASS",
     .expectedOutputPacket = "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGrU7AqAEBCsgBAXppAFIAAAAAAAAAAFAQIAAn4gAAa2F0cmFuIHRlc3QgcGt0"
    },
    // 14
    {// Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1",
     // dst="fc00:1::1")/TCP(sport=31337, dport=82,flags="A")/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAACMGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUgAAAAAAAAAAUBAgAP1NAABrYXRyYW4gdGVzdCBwa3Q=",
     .description = "pass of v6 packet with dst not equal to any configured VIP",
     .expectedReturnValue = "XDP_PASS",
     .expectedOutputPacket = "AgAAAAAAAQAAAAAAht1gAAAAACMGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUgAAAAAAAAAAUBAgAP1NAABrYXRyYW4gdGVzdCBwa3Q="
    },
    // 15
    {// Ether(src="0x1", dst="0x2")/ARP()
     .inputPacket = "AgAAAAAAAQAAAAAACAYAAQgABgQAAQAAAAAAAAAAAAAAAAAAAAAAAAAA",
     .description = "pass of arp packet",
     .expectedReturnValue = "XDP_PASS",
     .expectedOutputPacket = "AgAAAAAAAQAAAAAACAYAAQgABgQAAQAAAAAAAAAAAAAAAAAAAAAAAAAA"
    },
    // 16
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1",
     // dst="10.200.1.1")/TCP(sport=31337, dport=80, flags="A")/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGrU7AqAEBCsgBAXppAFAAAAAAAAAAAFAQIAAn5AAAa2F0cmFuIHRlc3QgcGt0",
     .description = "LRU hit",
     .expectedReturnValue = "XDP_TX",
     .expectedOutputPacket = "AADerb6vAgAAAAAACABFAABTAAAAAEARWXMKAA0lCgAAA2h7Jp4APxzLRQAANwABAABABq1OwKgBAQrIAQF6aQBQAAAAAAAAAABQECAAJ+QAAGthdHJhbiB0ZXN0IHBrdA=="
    },
    // 17
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1",
     // dst="10.200.1.4")/TCP(sport=31337, dport=42, flags="A")/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGrUvAqAEBCsgBBHppACoAAAAAAAAAAFAQIAAoBwAAa2F0cmFuIHRlc3QgcGt0",
     .description = "packet #1 dst port hashing only",
     .expectedReturnValue = "XDP_TX",
     .expectedOutputPacket = "AADerb6vAgAAAAAACABFAABTAAAAAEARWXQKAA0lCgAAAml6Jp4APxvQRQAANwABAABABq1LwKgBAQrIAQR6aQAqAAAAAAAAAABQECAAKAcAAGthdHJhbiB0ZXN0IHBrdA=="
    },
    // 18
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.100",
     // dst="10.200.1.4")/TCP(sport=1337, dport=42, flags="A")/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGrOjAqAFkCsgBBAU5ACoAAAAAAAAAAFAQIACc1AAAa2F0cmFuIHRlc3QgcGt0",
     .description = "packet #2 dst port hashing only",
     .expectedReturnValue = "XDP_TX",
     .expectedOutputPacket = "AADerb6vAgAAAAAACABFAABTAAAAAEARWXQKAA0lCgAAAjkFJp4AP0yoRQAANwABAABABqzowKgBZArIAQQFOQAqAAAAAAAAAABQECAAnNQAAGthdHJhbiB0ZXN0IHBrdA=="
    },
    // 19
    {// Ether(src="0x1", dst="0x2")/IP(src="172.16.1.1",
     // dst="172.16.100.1")/UDP(sport=1337, dport=6080)/IP(src="192.168.1.1",
     // dst="10.200.1.1")/UDP(sport=31337, dport=80)/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAACABFAABHAAEAAEARvYKsEAEBrBBkAQU5F8AAM/MGRQAAKwABAABAEa1PwKgBAQrIAQF6aQBQABeX3mthdHJhbiB0ZXN0IHBrdA==",
     .description = "gue ipv4 inner ipv4 outer packet",
     .expectedReturnValue = "XDP_PASS",
     .expectedOutputPacket = "AgAAAAAAAQAAAAAACABFAABHAAEAAEARvYKsEAEBrBBkAQU5F8AAM/MGRQAAKwABAABAEa1PwKgBAQrIAQF6aQBQABeX3mthdHJhbiB0ZXN0IHBrdA=="
    },
    // 20
    {// Ether(src="0x1", dst="0x2")/IPv6(src="100::1",
     // dst="100::2")/UDP(sport=1337, dport=6080)/IPv6(src="fc00:2::1",
     // dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAAFMRQAEAAAAAAAAAAAAAAAAAAAEBAAAAAAAAAAAAAAAAAAACBTkXwABTehJgAAAAACMGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1PAABrYXRyYW4gdGVzdCBwa3Q=",
     .description = "gue ipv6 inner ipv6 outer packet",
     .expectedReturnValue = "XDP_PASS",
     .expectedOutputPacket = "AgAAAAAAAQAAAAAAht1gAAAAAFMRQAEAAAAAAAAAAAAAAAAAAAEBAAAAAAAAAAAAAAAAAAACBTkXwABTehJgAAAAACMGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1PAABrYXRyYW4gdGVzdCBwa3Q="
    },
    // 21
    {// Ether(src="0x1", dst="0x2")/IPv6(src="100::1",
     // dst="100::2")/UDP(sport=1337, dport=6080)/IP(src="192.168.1.1",
     // dst="10.200.1.1")/UDP(sport=31337, dport=80)/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAADMRQAEAAAAAAAAAAAAAAAAAAAEBAAAAAAAAAAAAAAAAAAACBTkXwAAzridFAAArAAEAAEARrU/AqAEBCsgBAXppAFAAF5fea2F0cmFuIHRlc3QgcGt0",
     .description = "gue ipv4 inner ipv6 outer packet",
     .expectedReturnValue = "XDP_PASS",
     .expectedOutputPacket = "AgAAAAAAAQAAAAAAht1gAAAAADMRQAEAAAAAAAAAAAAAAAAAAAEBAAAAAAAAAAAAAAAAAAACBTkXwAAzridFAAArAAEAAEARrU/AqAEBCsgBAXppAFAAF5fea2F0cmFuIHRlc3QgcGt0"
    },
    // 22
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.42",
     // dst="10.200.1.5")/UDP(sport=31337,
     // dport=443)/'\xcf\xfa\xce\xb0\x01\x08\x41\x02\x03\x04\x05\x06\x07\x00\x00\x01\x11\x01quic
     // data\x00@'
     .inputPacket = "AgAAAAAAAQAAAAAACABFAAA5AAEAAEARrRTAqAEqCsgBBXppAbsAJbdsz/rOsAEIQQIDBAUGBwAAAREBcXVpYyBkYXRhAEA=",
     .description = "QUIC: long header. Client Initial type. LRU miss",
     .expectedReturnValue = "XDP_TX",
     .expectedOutputPacket = "AADerb6vAgAAAAAACABFAABVAAAAAEARWXIKAA0lCgAAAmhQJp4AQR0tRQAAOQABAABAEa0UwKgBKgrIAQV6aQG7ACW3bM/6zrABCEECAwQFBgcAAAERAXF1aWMgZGF0YQBA"
    },
    // 23
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.42",
     // dst="10.200.1.5")/UDP(sport=31337,
     // dport=443)/'\xdf\xfa\xce\xb0\x01\x08\x43\xFF\x33\x44\x55\x66\x77\x88\x00\x01\x11\x01quic
     // data\x00@'
     .inputPacket = "AgAAAAAAAQAAAAAACABFAAA5AAEAAEARrRTAqAEqCsgBBXppAbsAJbNG3/rOsAEIQ/8zRFVmd4gAAREBcXVpYyBkYXRhAEA=",
     .description = "QUIC: long header. 0-RTT Protected. CH. LRU hit.",
     .expectedReturnValue = "XDP_TX",
     .expectedOutputPacket = "AADerb6vAgAAAAAACABFAABVAAAAAEARWXIKAA0lCgAAAmhQJp4AQR0tRQAAOQABAABAEa0UwKgBKgrIAQV6aQG7ACWzRt/6zrABCEP/M0RVZneIAAERAXF1aWMgZGF0YQBA"
    },
    // 24
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.42",
     // dst="10.200.1.5")/UDP(sport=31337,
     // dport=443)/'\xef\xfa\xce\xb0\x01\x08\x41\x00\x03\x04\x05\x06\x07\x00\x00\x01\x11\x01quic
     // data\x00@'
     .inputPacket = "AgAAAAAAAQAAAAAACABFAAA5AAEAAEARrRTAqAEqCsgBBXppAbsAJZRt7/rOsAEIQQADBAUGBwAAAREBcXVpYyBkYXRhAEA=",
     .description = "QUIC: long header. Handshake. v4 vip v6 real. Conn Id V1 based. server id is 1024 mapped to fc00::1.",
     .expectedReturnValue = "XDP_TX",
     .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAEERQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAABe0MmngBB/R9FAAA5AAEAAEARrRTAqAEqCsgBBXppAbsAJZRt7/rOsAEIQQADBAUGBwAAAREBcXVpYyBkYXRhAEA="
    },
    // 25
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.42",
     // dst="10.200.1.5")/UDP(sport=31337,
     // dport=443)/'\xff\xfa\xce\xb0\x01\x08\x41\x00\x03\x04\x05\x06\x07\x00\x00\x01\x11\x01quic
     // data\x00@'
     .inputPacket = "AgAAAAAAAQAAAAAACABFAAA5AAEAAEARrRTAqAEqCsgBBXppAbsAJYRt//rOsAEIQQADBAUGBwAAAREBcXVpYyBkYXRhAEA=",
     .description = "QUIC: long header. Retry. v4 vip v6 real. Conn Id V1 based. server id is 1024 mapped to fc00::1.",
     .expectedReturnValue = "XDP_TX",
     .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAEERQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAABe0MmngBB/R9FAAA5AAEAAEARrRTAqAEqCsgBBXppAbsAJYRt//rOsAEIQQADBAUGBwAAAREBcXVpYyBkYXRhAEA="
    },
    // 26
    {// Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::42",
     // dst="fc00:1::2")/UDP(sport=31337,
     // dport=443)/'\xcf\xfa\xce\xb0\x01\x08\x44\x01\x03\x04\x05\x06\x07\x00\x00\x01\x11\x01quic
     // data\x00@'
     .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAACURQPwAAAIAAAAAAAAAAAAAAEL8AAABAAAAAAAAAAAAAAACemkBuwAlicTP+s6wAQhEAQMEBQYHAAABEQFxdWljIGRhdGEAQA==",
     .description = "QUIC: long header. client initial. v6 vip v6 real. LRU miss",
     .expectedReturnValue = "XDP_TX",
     .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAFURQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAABemkmngBVvsxgAAAAACURQPwAAAIAAAAAAAAAAAAAAEL8AAABAAAAAAAAAAAAAAACemkBuwAlicTP+s6wAQhEAQMEBQYHAAABEQFxdWljIGRhdGEAQA=="
    },
    // 27
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.42",
     // dst="10.200.1.5")/UDP(sport=31337, dport=443)/'\x00'
     .inputPacket = "AgAAAAAAAQAAAAAACABFAAAdAAEAAEARrTDAqAEqCsgBBXppAbsACbYYAA==",
     .description = "QUIC: short header. No connection id. CH. LRU hit",
     .expectedReturnValue = "XDP_TX",
     .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAACURQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAABe0MmngAl/TtFAAAdAAEAAEARrTDAqAEqCsgBBXppAbsACbYYAA=="
    },
    // 28
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.42",
     // dst="10.200.1.5")/UDP(sport=31337,
     // dport=443)/'\x00\x41\x00\x83\x04\x05\x06\x07\x00@'
     .inputPacket = "AgAAAAAAAQAAAAAACABFAAAmAAEAAEARrSfAqAEqCsgBBXppAbsAEqr2AEEAgwQFBgcAQA==",
     .description = "QUIC: short header w/ connection id",
     .expectedReturnValue = "XDP_TX",
     .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAC4RQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAACe0MmngAu/TFFAAAmAAEAAEARrSfAqAEqCsgBBXppAbsAEqr2AEEAgwQFBgcAQA=="
    },
    // 29
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.42",
     // dst="10.200.1.5")/UDP(sport=31337,
     // dport=443)/'\x00\x41\x11\x00\x00\x00\x00\x00\x00@'
     .inputPacket = "AgAAAAAAAQAAAAAACABFAAAmAAEAAEARrSfAqAEqCsgBBXppAbsAEqSFAEERAAAAAAAAQA==",
     .description = "QUIC: short header w/ connection 1092 id but non-existing mapping. LRU hit",
     .expectedReturnValue = "XDP_TX",
     .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAC4RQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAACe0MmngAu/TFFAAAmAAEAAEARrSfAqAEqCsgBBXppAbsAEqSFAEERAAAAAAAAQA=="
    },
    // 30
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.42",
     // dst="10.200.1.5")/UDP(sport=31337,
     // dport=443)/'\x00\x40\x00\x03\x04\x05\x06\x07\x00@'
     .inputPacket = "AgAAAAAAAQAAAAAACABFAAAmAAEAAEARrSfAqAEqCsgBBXppAbsAEqt3AEAAAwQFBgcAQA==",
     .description = "QUIC: short header w/ conn id. host id = 0. CH. LRU hit",
     .expectedReturnValue = "XDP_TX",
     .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAC4RQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAACe0MmngAu/TFFAAAmAAEAAEARrSfAqAEqCsgBBXppAbsAEqt3AEAAAwQFBgcAQA=="
    },
    // 31
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.1",
     // tos=0x8c)/TCP(sport=31337, dport=80, flags="A")/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAACABFjAA3AAEAAEAGrMLAqAEBCsgBAXppAFAAAAAAAAAAAFAQIAAn5AAAa2F0cmFuIHRlc3QgcGt0",
     .description = "packet to TCP based v4 VIP (and v4 real) + ToS in IPV4",
     .expectedReturnValue = "XDP_TX",
     .expectedOutputPacket = "AADerb6vAgAAAAAACABFjABTAAAAAEARWOcKAA0lCgAAA2h7Jp4APxzLRYwANwABAABABqzCwKgBAQrIAQF6aQBQAAAAAAAAAABQECAAJ+QAAGthdHJhbiB0ZXN0IHBrdA=="
    },
    // 32
    {// Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1", dst="fc00:1::1",
     // tc=0x8c)/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAAht1owAAAACMGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1PAABrYXRyYW4gdGVzdCBwa3Q=",
     .description = "packet to TCP based v6 VIP (and v6 real) with ToS / tc set",
     .expectedReturnValue = "XDP_TX",
     .expectedOutputPacket = "AADerb6vAgAAAAAAht1owAAAAFMRQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAADemkmngBTwQNowAAAACMGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1PAABrYXRyYW4gdGVzdCBwa3Q="
    },
    // 33
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.42",
     // dst="10.200.1.5")/UDP(sport=31337,
     // dport=443)/b'\x00\x80\x03\x04\x02\x05\x06\x07\x00@'
     .inputPacket = "AgAAAAAAAQAAAAAACABFAAAmAAEAAEARrSfAqAEqCsgBBXppAbsAEqo2AIADBAIFBgcAQA==",
     .description = "QUIC: short header w/ connection id. CIDv2",
     .expectedReturnValue = "XDP_TX",
     .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAC4RQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAACe0MmngAu/TFFAAAmAAEAAEARrSfAqAEqCsgBBXppAbsAEqo2AIADBAIFBgcAQA=="
    },
    // 34
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.42",
     // dst="10.200.1.5")/UDP(sport=31337,
     // dport=443)/b'\x00\x80\x03\x04\x44\x00\x00\x00\x00@'
     .inputPacket = "AgAAAAAAAQAAAAAACABFAAAmAAEAAEARrSfAqAEqCsgBBXppAbsAEm5CAIADBEQAAAAAQA==",
     .description = "QUIC: short header w/ connection id 197700 but non-existing mapping. CIDv2. LRU hit.",
     .expectedReturnValue = "XDP_TX",
     .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAC4RQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAACe0MmngAu/TFFAAAmAAEAAEARrSfAqAEqCsgBBXppAbsAEm5CAIADBEQAAAAAQA=="
    },
    // 35
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1",
     // dst="10.200.1.99")/TCP(sport=31337, dport=80, flags="A")/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGrOzAqAEBCsgBY3ppAFAAAAAAAAAAAFAQIAAnggAAa2F0cmFuIHRlc3QgcGt0",
     .description = "packet to TCP based v4 VIP that is not initialzed",
     .expectedReturnValue = "XDP_DROP",
     .expectedOutputPacket = "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGrOzAqAEBCsgBY3ppAFAAAAAAAAAAAFAQIAAnggAAa2F0cmFuIHRlc3QgcGt0"
    },
    // 36
    {// Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1",
     // dst="fc00:1::11")/UDP(sport=31337, dport=80)/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAABMRQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAARemkAUAATUc5rYXRyYW4gdGVzdA==",
     .description = "packet to UDP based v6 VIP that is not initialized",
     .expectedReturnValue = "XDP_DROP",
     .expectedOutputPacket = "AgAAAAAAAQAAAAAAht1gAAAAABMRQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAARemkAUAATUc5rYXRyYW4gdGVzdA=="
    },

};

} // namespace testing
} // namespace katran
