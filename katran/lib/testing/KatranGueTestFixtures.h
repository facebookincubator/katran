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
#include <utility>

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
const std::vector<std::pair<std::string, std::string>> inputGueTestFixtures = {
  //1
  {
    // Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.1")/UDP(sport=31337, dport=80)/"katran test pkt"
    "AgAAAAAAAQAAAAAACABFAAArAAEAAEARrU/AqAEBCsgBAXppAFAAF5fea2F0cmFuIHRlc3QgcGt0",
    "packet to UDP based v4 VIP (and v4 real)"
  },
  //2
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.1")/TCP(sport=31337, dport=80, flags="A")/"katran test pkt"
    "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGrU7AqAEBCsgBAXppAFAAAAAAAAAAAFAQIAAn5AAAa2F0cmFuIHRlc3QgcGt0",
    "packet to TCP based v4 VIP (and v4 real)"
  },
  //3
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.2")/TCP(sport=31337, dport=42, flags="A")/"katran test pkt"
    "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGrU3AqAEBCsgBAnppACoAAAAAAAAAAFAQIAAoCQAAa2F0cmFuIHRlc3QgcGt0",
    "packet to TCP based v4 VIP (and v4 real; any dst ports)."
  },
  //4
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.3")/TCP(sport=31337, dport=80, flags="A")/"katran test pkt"
    "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGrUzAqAEBCsgBA3ppAFAAAAAAAAAAAFAQIAAn4gAAa2F0cmFuIHRlc3QgcGt0",
    "packet to TCP based v4 VIP (and v6 real)"
  },
  //5
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1", dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
    "AgAAAAAAAQAAAAAAht1gAAAAACMGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1PAABrYXRyYW4gdGVzdCBwa3Q=",
    "packet to TCP based v6 VIP (and v6 real)"
  },
  //6
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.3")/ICMP(type="echo-request")
    "AgAAAAAAAQAAAAAACABFAAAcAAEAAEABrWzAqAEBCsgBAwgA9/8AAAAA",
    "v4 ICMP echo-request"
  },
  //7
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1", dst="fc00:1::1")/ICMPv6EchoRequest()
    "AgAAAAAAAQAAAAAAht1gAAAAAAg6QPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABgACHtgAAAAA=",
    "v6 ICMP echo-request"
  },
  //8
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.100.1", dst="10.200.1.1")/ICMP(type="dest-unreach", code="fragmentation-needed")/IP(src="10.200.1.1", dst="192.168.1.1")/TCP(sport=80, dport=31337)/"test katran pkt"
    "AgAAAAAAAQAAAAAACABFAABTAAEAAEABSjfAqGQBCsgBAQMEypcAAAAARQAANwABAABABq1OCsgBAcCoAQEAUHppAAAAAAAAAABQAiAAGQEAAHRlc3Qga2F0cmFuIHBrdA==",
    "v4 ICMP dest-unreachabe fragmentation-needed"
  },
  //9
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="fc00:200::1", dst="fc00:1::1")/ICMPv6PacketTooBig()/IPv6(src="fc00:1::1", dst="fc00:2::1")/TCP(sport=80,dport=31337)/"katran test packet"
    "AgAAAAAAAQAAAAAAht1gAAAAAFY6QPwAAgAAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABAgCYMAAABQBgAAAAACYGQPwAAAEAAAAAAAAAAAAAAAH8AAACAAAAAAAAAAAAAAABAFB6aQAAAAAAAAAAUAIgAKiFAABrYXRyYW4gdGVzdCBwYWNrZXQ=",
    "v6 ICMP packet-too-big"
  },
  //10
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.1",ihl=6)/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
    "AgAAAAAAAQAAAAAACABGAAA3AAEAAEAGrE7AqAEBCsgBAXppAFAAAAAAAAAAAFAQIAAn5AAAa2F0cmFuIHRlc3QgcGt0",
    "drop of IPv4 packet w/ options"
  },
  //11
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.1",ihl=5,flags="MF")/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
    "AgAAAAAAAQAAAAAACABFAAA3AAEgAEAGjU7AqAEBCsgBAXppAFAAAAAAAAAAAFAQIAAn5AAAa2F0cmFuIHRlc3QgcGt0",
    "drop of IPv4 fragmented packet"
  },
  //12
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1", dst="fc00:1::1",nh=44)/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
    "AgAAAAAAAQAAAAAAht1gAAAAACMsQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1PAABrYXRyYW4gdGVzdCBwa3Q=",
    "drop of IPv6 fragmented packet"
  },
  //13
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.1",ihl=5)/TCP(sport=31337, dport=82,flags="A")/"katran test pkt"
    "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGrU7AqAEBCsgBAXppAFIAAAAAAAAAAFAQIAAn4gAAa2F0cmFuIHRlc3QgcGt0",
    "pass of v4 packet with dst not equal to any configured VIP"
  },
  //14
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1", dst="fc00:1::1")/TCP(sport=31337, dport=82,flags="A")/"katran test pkt"
    "AgAAAAAAAQAAAAAAht1gAAAAACMGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUgAAAAAAAAAAUBAgAP1NAABrYXRyYW4gdGVzdCBwa3Q=",
    "pass of v6 packet with dst not equal to any configured VIP"
  },
  //15
  {
    //Ether(src="0x1", dst="0x2")/ARP()
    "AgAAAAAAAQAAAAAACAYAAQgABgQAAQAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "pass of arp packet"
  },
  //16
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.1")/TCP(sport=31337, dport=80, flags="A")/"katran test pkt"
    "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGrU7AqAEBCsgBAXppAFAAAAAAAAAAAFAQIAAn5AAAa2F0cmFuIHRlc3QgcGt0",
    "LRU hit"
  },
  //17
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.4")/TCP(sport=31337, dport=42, flags="A")/"katran test pkt"
    "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGrUvAqAEBCsgBBHppACoAAAAAAAAAAFAQIAAoBwAAa2F0cmFuIHRlc3QgcGt0",
    "packet #1 dst port hashing only"
  },
  //18
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.100", dst="10.200.1.4")/TCP(sport=1337, dport=42, flags="A")/"katran test pkt"
    "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGrOjAqAFkCsgBBAU5ACoAAAAAAAAAAFAQIACc1AAAa2F0cmFuIHRlc3QgcGt0",
    "packet #2 dst port hashing only"
  },
  //19
  {
    //Ether(src="0x1", dst="0x2")/IP(src="172.16.1.1", dst="172.16.100.1")/UDP(sport=1337, dport=6080)/IP(src="192.168.1.1", dst="10.200.1.1")/UDP(sport=31337, dport=80)/"katran test pkt"
    "AgAAAAAAAQAAAAAACABFAABHAAEAAEARvYKsEAEBrBBkAQU5F8AAM/MGRQAAKwABAABAEa1PwKgBAQrIAQF6aQBQABeX3mthdHJhbiB0ZXN0IHBrdA==",
    "gue ipv4 inner ipv4 outer packet"

  },
  //20
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="100::1", dst="100::2")/UDP(sport=1337, dport=6080)/IPv6(src="fc00:2::1", dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
    "AgAAAAAAAQAAAAAAht1gAAAAAFMRQAEAAAAAAAAAAAAAAAAAAAEBAAAAAAAAAAAAAAAAAAACBTkXwABTehJgAAAAACMGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1PAABrYXRyYW4gdGVzdCBwa3Q=",
    "gue ipv6 inner ipv6 outer packet"
  },
  //21
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="100::1", dst="100::2")/UDP(sport=1337, dport=6080)/IP(src="192.168.1.1", dst="10.200.1.1")/UDP(sport=31337, dport=80)/"katran test pkt"
    "AgAAAAAAAQAAAAAAht1gAAAAADMRQAEAAAAAAAAAAAAAAAAAAAEBAAAAAAAAAAAAAAAAAAACBTkXwAAzridFAAArAAEAAEARrU/AqAEBCsgBAXppAFAAF5fea2F0cmFuIHRlc3QgcGt0",
    "gue ipv4 inner ipv6 outer packet"
  },
  //22
  {
    // Ether(src="0x1", dst="0x2")/IP(src="192.168.1.42", dst="10.200.1.5")/UDP(sport=31337, dport=443)/'\xcf\xfa\xce\xb0\x01\x08\x41\x02\x03\x04\x05\x06\x07\x00\x00\x01\x11\x01quic data\x00@'
    "AgAAAAAAAQAAAAAACABFAAA5AAEAAEARrRTAqAEqCsgBBXppAbsAJbdsz/rOsAEIQQIDBAUGBwAAAREBcXVpYyBkYXRhAEA=",
    "QUIC: long header. Client Initial type. LRU miss"
  },
  //23
  {
    // Ether(src="0x1", dst="0x2")/IP(src="192.168.1.42", dst="10.200.1.5")/UDP(sport=31337, dport=443)/'\xdf\xfa\xce\xb0\x01\x08\x43\xFF\x33\x44\x55\x66\x77\x88\x00\x01\x11\x01quic data\x00@'
    "AgAAAAAAAQAAAAAACABFAAA5AAEAAEARrRTAqAEqCsgBBXppAbsAJbNG3/rOsAEIQ/8zRFVmd4gAAREBcXVpYyBkYXRhAEA=",
    "QUIC: long header. 0-RTT Protected. CH. LRU hit."
  },
  //24
  {
    // Ether(src="0x1", dst="0x2")/IP(src="192.168.1.42", dst="10.200.1.5")/UDP(sport=31337, dport=443)/'\xef\xfa\xce\xb0\x01\x08\x44\x01\x03\x04\x05\x06\x07\x00\x00\x01\x11\x01quic data\x00@'
    "AgAAAAAAAQAAAAAACABFAAA5AAEAAEARrRTAqAEqCsgBBXppAbsAJZRt7/rOsAEIRAEDBAUGBwAAAREBcXVpYyBkYXRhAEA=",
    "QUIC: long header. Handshake. v4 vip v6 real. Conn Id based."
  },
  //25
  {
    // Ether(src="0x1", dst="0x2")/IP(src="192.168.1.42", dst="10.200.1.5")/UDP(sport=31337, dport=443)/'\xff\xfa\xce\xb0\x01\x08\x44\x01\x03\x04\x05\x06\x07\x00\x00\x01\x11\x01quic data\x00@'
    "AgAAAAAAAQAAAAAACABFAAA5AAEAAEARrRTAqAEqCsgBBXppAbsAJYRt//rOsAEIRAEDBAUGBwAAAREBcXVpYyBkYXRhAEA=",
    "QUIC: long header. Retry. v4 vip v6 real. Conn Id based."
  },
  //26
  {
    // Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::42", dst="fc00:1::2")/UDP(sport=31337, dport=443)/'\xcf\xfa\xce\xb0\x01\x08\x44\x01\x03\x04\x05\x06\x07\x00\x00\x01\x11\x01quic data\x00@'
    "AgAAAAAAAQAAAAAAht1gAAAAACURQPwAAAIAAAAAAAAAAAAAAEL8AAABAAAAAAAAAAAAAAACemkBuwAlicTP+s6wAQhEAQMEBQYHAAABEQFxdWljIGRhdGEAQA==",
    "QUIC: long header. client initial. v6 vip v6 real. LRU miss"
  },
  //27
  {
    // Ether(src="0x1", dst="0x2")/IP(src="192.168.1.42", dst="10.200.1.5")/UDP(sport=31337, dport=443)/'\x00'
    "AgAAAAAAAQAAAAAACABFAAAdAAEAAEARrTDAqAEqCsgBBXppAbsACbYYAA==",
    "QUIC: short header. No connection id. CH. LRU hit"
  },
  //28
  {
    // Ether(src="0x1", dst="0x2")/IP(src="192.168.1.42", dst="10.200.1.5")/UDP(sport=31337, dport=443)/'\x00\x41\x00\x83\x04\x05\x06\x07\x00@'
    "AgAAAAAAAQAAAAAACABFAAAmAAEAAEARrSfAqAEqCsgBBXppAbsAEqr2AEEAgwQFBgcAQA==",
    "QUIC: short header w/ connection id"
  },
  //29
  {
    // Ether(src="0x1", dst="0x2")/IP(src="192.168.1.42", dst="10.200.1.5")/UDP(sport=31337, dport=443)/'\x00\x41\x11\x00\x00\x00\x00\x00\x00@'
    "AgAAAAAAAQAAAAAACABFAAAmAAEAAEARrSfAqAEqCsgBBXppAbsAEqSFAEERAAAAAAAAQA==",
    "QUIC: short header w/ connection id but non-existing mapping"
  },
  //30
  {
    // Ether(src="0x1", dst="0x2")/IP(src="192.168.1.42", dst="10.200.1.5")/UDP(sport=31337, dport=443)/'\x00\x40\x00\x03\x04\x05\x06\x07\x00@'
    "AgAAAAAAAQAAAAAACABFAAAmAAEAAEARrSfAqAEqCsgBBXppAbsAEqt3AEAAAwQFBgcAQA==",
    "QUIC: short header w/ conn id. host id = 0. CH. LRU hit"
  },
  //31
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.1", tos=0x8c)/TCP(sport=31337, dport=80, flags="A")/"katran test pkt"
    "AgAAAAAAAQAAAAAACABFjAA3AAEAAEAGrMLAqAEBCsgBAXppAFAAAAAAAAAAAFAQIAAn5AAAa2F0cmFuIHRlc3QgcGt0",
    "packet to TCP based v4 VIP (and v4 real) + ToS in IPV4"
  },
  //32
  {
    // Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1", dst="fc00:1::1", tc=0x8c)/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
    "AgAAAAAAAQAAAAAAht1owAAAACMGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1PAABrYXRyYW4gdGVzdCBwa3Q=",
    "packet to TCP based v6 VIP (and v6 real) with ToS / tc set"
  },
};

const std::vector<std::pair<std::string, std::string>> outputGueTestFixtures = {
  //1
  {
    "AADerb6vAgAAAAAACABFAABHAAAAAEARWX8KAA0lCgAAA2h7F8AAMwAARQAAKwABAABAEa1PwKgBAQrIAQF6aQBQABeX3mthdHJhbiB0ZXN0IHBrdA==",
    "XDP_TX"
  },
  //2
  {
    "AADerb6vAgAAAAAACABFAABTAAAAAEARWXMKAA0lCgAAA2h7F8AAPwAARQAANwABAABABq1OwKgBAQrIAQF6aQBQAAAAAAAAAABQECAAJ+QAAGthdHJhbiB0ZXN0IHBrdA==",
    "XDP_TX"
  },
  //3
  {
    "AADerb6vAgAAAAAACABFAABTAAAAAEARWXQKAA0lCgAAAmh7F8AAPwAARQAANwABAABABq1NwKgBAQrIAQJ6aQAqAAAAAAAAAABQECAAKAkAAGthdHJhbiB0ZXN0IHBrdA==",
    "XDP_TX"
  },
  //4
  {
    "AADerb6vAgAAAAAAht1gAAAAAD8RQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAABe2gXwAA/AABFAAA3AAEAAEAGrUzAqAEBCsgBA3ppAFAAAAAAAAAAAFAQIAAn4gAAa2F0cmFuIHRlc3QgcGt0",
    "XDP_TX"
  },
  //5
  {
    "AADerb6vAgAAAAAAht1gAAAAAFMRQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAADemkXwABTAABgAAAAACMGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1PAABrYXRyYW4gdGVzdCBwa3Q=",
    "XDP_TX"
  },
  //6
  {
    "AQAAAAAAAgAAAAAACABFAAAcAAEAAEABrWwKyAEDwKgBAQAA//8AAAAA",
    "XDP_TX",
  },
  //7
  {
    "AQAAAAAAAgAAAAAAht1gAAAAAAg6QPwAAAEAAAAAAAAAAAAAAAH8AAACAAAAAAAAAAAAAAABgQCGtgAAAAA=",
    "XDP_TX"
  },
  //8
  {
    "AADerb6vAgAAAAAACABFAABvAAAAAEARWVcKAA0lCgAAA2h7F8AAWwAARQAAUwABAABAAUo3wKhkAQrIAQEDBMqXAAAAAEUAADcAAQAAQAatTgrIAQHAqAEBAFB6aQAAAAAAAAAAUAIgABkBAAB0ZXN0IGthdHJhbiBwa3Q=",
    "XDP_TX"
  },
  //9
  {
    "AADerb6vAgAAAAAAht1gAAAAAIYRQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAADemkXwACGAABgAAAAAFY6QPwAAgAAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABAgCYMAAABQBgAAAAACYGQPwAAAEAAAAAAAAAAAAAAAH8AAACAAAAAAAAAAAAAAABAFB6aQAAAAAAAAAAUAIgAKiFAABrYXRyYW4gdGVzdCBwYWNrZXQ=",
    "XDP_TX"
  },
  //10
  {
    "AgAAAAAAAQAAAAAACABGAAA3AAEAAEAGrE7AqAEBCsgBAXppAFAAAAAAAAAAAFAQIAAn5AAAa2F0cmFuIHRlc3QgcGt0",
    "XDP_DROP"
  },
  //11
  {
    "AgAAAAAAAQAAAAAACABFAAA3AAEgAEAGjU7AqAEBCsgBAXppAFAAAAAAAAAAAFAQIAAn5AAAa2F0cmFuIHRlc3QgcGt0",
    "XDP_DROP"
  },
  //12
  {
    "AgAAAAAAAQAAAAAAht1gAAAAACMsQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1PAABrYXRyYW4gdGVzdCBwa3Q=",
    "XDP_DROP"
  },
  //13
  {
    "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGrU7AqAEBCsgBAXppAFIAAAAAAAAAAFAQIAAn4gAAa2F0cmFuIHRlc3QgcGt0",
    "XDP_PASS"
  },
  //14
  {
    "AgAAAAAAAQAAAAAAht1gAAAAACMGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUgAAAAAAAAAAUBAgAP1NAABrYXRyYW4gdGVzdCBwa3Q=",
    "XDP_PASS"
  },
  //15
  {
    "AgAAAAAAAQAAAAAACAYAAQgABgQAAQAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "XDP_PASS"
  },
  //16
  {
    "AADerb6vAgAAAAAACABFAABTAAAAAEARWXMKAA0lCgAAA2h7F8AAPwAARQAANwABAABABq1OwKgBAQrIAQF6aQBQAAAAAAAAAABQECAAJ+QAAGthdHJhbiB0ZXN0IHBrdA==",
    "XDP_TX"
  },
  //17
  {
    "AADerb6vAgAAAAAACABFAABTAAAAAEARWXQKAA0lCgAAAioAF8AAPwAARQAANwABAABABq1LwKgBAQrIAQR6aQAqAAAAAAAAAABQECAAKAcAAGthdHJhbiB0ZXN0IHBrdA==",
    "XDP_TX"
  },
  //18
  {
    "AADerb6vAgAAAAAACABFAABTAAAAAEARWXQKAA0lCgAAAioAF8AAPwAARQAANwABAABABqzowKgBZArIAQQFOQAqAAAAAAAAAABQECAAnNQAAGthdHJhbiB0ZXN0IHBrdA==",
    "XDP_TX"
  },
  //19
  {
    "AgAAAAAAAQAAAAAACABFAABHAAEAAEARvYKsEAEBrBBkAQU5F8AAM/MGRQAAKwABAABAEa1PwKgBAQrIAQF6aQBQABeX3mthdHJhbiB0ZXN0IHBrdA==",
    "XDP_PASS"

  },
  //20
  {
    "AgAAAAAAAQAAAAAAht1gAAAAAFMRQAEAAAAAAAAAAAAAAAAAAAEBAAAAAAAAAAAAAAAAAAACBTkXwABTehJgAAAAACMGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1PAABrYXRyYW4gdGVzdCBwa3Q=",
    "XDP_PASS"
  },
  //21
  {
    "AgAAAAAAAQAAAAAAht1gAAAAADMRQAEAAAAAAAAAAAAAAAAAAAEBAAAAAAAAAAAAAAAAAAACBTkXwAAzridFAAArAAEAAEARrU/AqAEBCsgBAXppAFAAF5fea2F0cmFuIHRlc3QgcGt0",
    "XDP_PASS"
  },
  //22
  {
    "AADerb6vAgAAAAAACABFAABVAAAAAEARWXIKAA0lCgAAAmhQF8AAQQAARQAAOQABAABAEa0UwKgBKgrIAQV6aQG7ACW3bM/6zrABCEECAwQFBgcAAAERAXF1aWMgZGF0YQBA",
    "XDP_TX"
  },
  //23
  {
    "AADerb6vAgAAAAAACABFAABVAAAAAEARWXIKAA0lCgAAAmhQF8AAQQAARQAAOQABAABAEa0UwKgBKgrIAQV6aQG7ACWzRt/6zrABCEP/M0RVZneIAAERAXF1aWMgZGF0YQBA",
    "XDP_TX"
  },
  //24
  {
    "AADerb6vAgAAAAAACABFAABVAAAAAEARWXMKAA0lCgAAAWhQF8AAQQAARQAAOQABAABAEa0UwKgBKgrIAQV6aQG7ACWUbe/6zrABCEQBAwQFBgcAAAERAXF1aWMgZGF0YQBA",
    "XDP_TX"
  },
  //25
  {
    "AADerb6vAgAAAAAACABFAABVAAAAAEARWXMKAA0lCgAAAWhQF8AAQQAARQAAOQABAABAEa0UwKgBKgrIAQV6aQG7ACWEbf/6zrABCEQBAwQFBgcAAAERAXF1aWMgZGF0YQBA",
    "XDP_TX"
  },
  //26
  {
    "AADerb6vAgAAAAAAht1gAAAAAFURQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAABemkXwABVAABgAAAAACURQPwAAAIAAAAAAAAAAAAAAEL8AAABAAAAAAAAAAAAAAACemkBuwAlicTP+s6wAQhEAQMEBQYHAAABEQFxdWljIGRhdGEAQA==",
    "XDP_TX"
  },
  //27
  {
    "AADerb6vAgAAAAAACABFAAA5AAAAAEARWY4KAA0lCgAAAmhQF8AAJQAARQAAHQABAABAEa0wwKgBKgrIAQV6aQG7AAm2GAA=",
    "XDP_TX"
  },
  //28
  {
    "AADerb6vAgAAAAAAht1gAAAAAC4RQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAACe0MXwAAuAABFAAAmAAEAAEARrSfAqAEqCsgBBXppAbsAEqr2AEEAgwQFBgcAQA==",
    "XDP_TX"
  },
  //29
  {
    "AADerb6vAgAAAAAACABFAABCAAAAAEARWYYKAA0lCgAAAWhQF8AALgAARQAAJgABAABAEa0nwKgBKgrIAQV6aQG7ABKkhQBBEQAAAAAAAEA=",
    "XDP_TX"
  },
  //30
  {
    "AADerb6vAgAAAAAACABFAABCAAAAAEARWYUKAA0lCgAAAmhQF8AALgAARQAAJgABAABAEa0nwKgBKgrIAQV6aQG7ABKrdwBAAAMEBQYHAEA=",
    "XDP_TX"
  },
  //31
  {
    "AADerb6vAgAAAAAACABFjABTAAAAAEARWOcKAA0lCgAAA2h7F8AAPwAARYwANwABAABABqzCwKgBAQrIAQF6aQBQAAAAAAAAAABQECAAJ+QAAGthdHJhbiB0ZXN0IHBrdA==",
    "XDP_TX"
  },
  //32
  {
    "AADerb6vAgAAAAAAht1owAAAAFMRQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAADemkXwABTAABowAAAACMGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1PAABrYXRyYW4gdGVzdCBwa3Q=",
    "XDP_TX"
  },

};

} // namespace testing
} // namespace katran
