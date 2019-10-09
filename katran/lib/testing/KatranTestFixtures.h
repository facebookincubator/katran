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
const std::vector<std::pair<std::string, std::string>> inputTestFixtures = {
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
  // 3
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.1", tos=0x8c)/TCP(sport=31337, dport=80, flags="A")/"katran test pkt"
    "AgAAAAAAAQAAAAAACABFjAA3AAEAAEAGrMLAqAEBCsgBAXppAFAAAAAAAAAAAFAQIAAn5AAAa2F0cmFuIHRlc3QgcGt0",
    "packet to TCP based v4 VIP (and v4 real) + ToS in IPV4"
  },
  //4
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.2")/TCP(sport=31337, dport=42, flags="A")/"katran test pkt"
    "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGrU3AqAEBCsgBAnppACoAAAAAAAAAAFAQIAAoCQAAa2F0cmFuIHRlc3QgcGt0",
    "packet to TCP based v4 VIP (and v4 real; any dst ports)."
  },
  //5
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.3")/TCP(sport=31337, dport=80, flags="A")/"katran test pkt"
    "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGrUzAqAEBCsgBA3ppAFAAAAAAAAAAAFAQIAAn4gAAa2F0cmFuIHRlc3QgcGt0",
    "packet to TCP based v4 VIP (and v6 real)"
  },
  //6
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1", dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
    "AgAAAAAAAQAAAAAAht1gAAAAACMGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1PAABrYXRyYW4gdGVzdCBwa3Q=",
    "packet to TCP based v6 VIP (and v6 real)"
  },
  //7
  {
    // Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1", dst="fc00:1::1", tc=0x8c)/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
    "AgAAAAAAAQAAAAAAht1owAAAACMGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1PAABrYXRyYW4gdGVzdCBwa3Q=",
    "packet to TCP based v6 VIP (and v6 real) with ToS / tc set"
  },
  //8
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.3")/ICMP(type="echo-request")
    "AgAAAAAAAQAAAAAACABFAAAcAAEAAEABrWzAqAEBCsgBAwgA9/8AAAAA",
    "v4 ICMP echo-request"
  },
  //9
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1", dst="fc00:1::1")/ICMPv6EchoRequest()
    "AgAAAAAAAQAAAAAAht1gAAAAAAg6QPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABgACHtgAAAAA=",
    "v6 ICMP echo-request"
  },
  //10
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.100.1", dst="10.200.1.1")/ICMP(type="dest-unreach", code="fragmentation-needed")/IP(src="10.200.1.1", dst="192.168.1.1")/TCP(sport=80, dport=31337)/"test katran pkt"
    "AgAAAAAAAQAAAAAACABFAABTAAEAAEABSjfAqGQBCsgBAQMEypcAAAAARQAANwABAABABq1OCsgBAcCoAQEAUHppAAAAAAAAAABQAiAAGQEAAHRlc3Qga2F0cmFuIHBrdA==",
    "v4 ICMP dest-unreachabe fragmentation-needed"
  },
  //11
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="fc00:200::1", dst="fc00:1::1")/ICMPv6PacketTooBig()/IPv6(src="fc00:1::1", dst="fc00:2::1")/TCP(sport=80,dport=31337)/"katran test packet"
    "AgAAAAAAAQAAAAAAht1gAAAAAFY6QPwAAgAAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABAgCYMAAABQBgAAAAACYGQPwAAAEAAAAAAAAAAAAAAAH8AAACAAAAAAAAAAAAAAABAFB6aQAAAAAAAAAAUAIgAKiFAABrYXRyYW4gdGVzdCBwYWNrZXQ=",
    "v6 ICMP packet-too-big"
  },
  //12
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.1",ihl=6)/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
    "AgAAAAAAAQAAAAAACABGAAA3AAEAAEAGrE7AqAEBCsgBAXppAFAAAAAAAAAAAFAQIAAn5AAAa2F0cmFuIHRlc3QgcGt0",
    "drop of IPv4 packet w/ options"
  },
  //13
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.1",ihl=5,flags="MF")/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
    "AgAAAAAAAQAAAAAACABFAAA3AAEgAEAGjU7AqAEBCsgBAXppAFAAAAAAAAAAAFAQIAAn5AAAa2F0cmFuIHRlc3QgcGt0",
    "drop of IPv4 fragmented packet"
  },
  //14
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1", dst="fc00:1::1",nh=44)/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
    "AgAAAAAAAQAAAAAAht1gAAAAACMsQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1PAABrYXRyYW4gdGVzdCBwa3Q=",
    "drop of IPv6 fragmented packet"
  },
  //15
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.1",ihl=5)/TCP(sport=31337, dport=82,flags="A")/"katran test pkt"
    "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGrU7AqAEBCsgBAXppAFIAAAAAAAAAAFAQIAAn4gAAa2F0cmFuIHRlc3QgcGt0",
    "pass of v4 packet with dst not equal to any configured VIP"
  },
  //16
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1", dst="fc00:1::1")/TCP(sport=31337, dport=82,flags="A")/"katran test pkt"
    "AgAAAAAAAQAAAAAAht1gAAAAACMGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUgAAAAAAAAAAUBAgAP1NAABrYXRyYW4gdGVzdCBwa3Q=",
    "pass of v6 packet with dst not equal to any configured VIP"
  },
  //17
  {
    //Ether(src="0x1", dst="0x2")/ARP()
    "AgAAAAAAAQAAAAAACAYAAQgABgQAAQAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "pass of arp packet"
  },
  //18
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.1")/TCP(sport=31337, dport=80, flags="A")/"katran test pkt"
    "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGrU7AqAEBCsgBAXppAFAAAAAAAAAAAFAQIAAn5AAAa2F0cmFuIHRlc3QgcGt0",
    "LRU hit"
  },
  //19
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.4")/TCP(sport=31337, dport=42, flags="A")/"katran test pkt"
    "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGrUvAqAEBCsgBBHppACoAAAAAAAAAAFAQIAAoBwAAa2F0cmFuIHRlc3QgcGt0",
    "packet #1 dst port hashing only"
  },
  //20
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.100", dst="10.200.1.4")/TCP(sport=1337, dport=42, flags="A")/"katran test pkt"
    "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGrOjAqAFkCsgBBAU5ACoAAAAAAAAAAFAQIACc1AAAa2F0cmFuIHRlc3QgcGt0",
    "packet #2 dst port hashing only"
  },
  //21
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.4")/TCP(sport=31337, dport=42, flags="A")/"katran test pkt"
    "AgAAAAAAAQAAAAAACABFAAA/AAEAAEAEvZesEAEBrBBkAUUAACsAAQAAQBGtT8CoAQEKyAEBemkAUAAXl95rYXRyYW4gdGVzdCBwa3Q=",
    "ipinip packet"

  },
  //22
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="100::1", dst="100::2")/IPv6(src="fc00:2::1", dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
    "AgAAAAAAAQAAAAAAht1gAAAAAEspQAEAAAAAAAAAAAAAAAAAAAEBAAAAAAAAAAAAAAAAAAACYAAAAAAjBkD8AAACAAAAAAAAAAAAAAAB/AAAAQAAAAAAAAAAAAAAAXppAFAAAAAAAAAAAFAQIAD9TwAAa2F0cmFuIHRlc3QgcGt0",
    "ipv6inipv6 packet"
  },
  //23
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="100::1", dst="100::2")/IP(src="192.168.1.1", dst="10.200.1.1")/UDP(sport=31337, dport=80)/"katran test pkt"
    "AgAAAAAAAQAAAAAAht1gAAAAACsEQAEAAAAAAAAAAAAAAAAAAAEBAAAAAAAAAAAAAAAAAAACRQAAKwABAABAEa1PwKgBAQrIAQF6aQBQABeX3mthdHJhbiB0ZXN0IHBrdA==",
    "ipv4inipv6 packet"
  },
  //24
  {
    // Ether(src="0x1", dst="0x2")/IP(src="192.168.1.42", dst="10.200.1.5")/UDP(sport=31337, dport=443)/'\xcf\xfa\xce\xb0\x01\x08\x41\x02\x03\x04\x05\x06\x07\x00\x00\x01\x11\x01quic data\x00@'
    "AgAAAAAAAQAAAAAACABFAAA5AAEAAEARrRTAqAEqCsgBBXppAbsAJbdsz/rOsAEIQQIDBAUGBwAAAREBcXVpYyBkYXRhAEA=",
    "QUIC: long header. Client Initial type. LRU miss"
  },
  //25
  {
    // Ether(src="0x1", dst="0x2")/IP(src="192.168.1.42", dst="10.200.1.5")/UDP(sport=31337, dport=443)/'\xdf\xfa\xce\xb0\x01\x08\x43\xFF\x33\x44\x55\x66\x77\x88\x00\x01\x11\x01quic data\x00@'
    "AgAAAAAAAQAAAAAACABFAAA5AAEAAEARrRTAqAEqCsgBBXppAbsAJbNG3/rOsAEIQ/8zRFVmd4gAAREBcXVpYyBkYXRhAEA=",
    "QUIC: long header. 0-RTT Protected. CH. LRU hit."
  },
  //26
  {
    // Ether(src="0x1", dst="0x2")/IP(src="192.168.1.42", dst="10.200.1.5")/UDP(sport=31337, dport=443)/'\xef\xfa\xce\xb0\x01\x08\x44\x01\x03\x04\x05\x06\x07\x00\x00\x01\x11\x01quic data\x00@'
    "AgAAAAAAAQAAAAAACABFAAA5AAEAAEARrRTAqAEqCsgBBXppAbsAJZRt7/rOsAEIRAEDBAUGBwAAAREBcXVpYyBkYXRhAEA=",
    "QUIC: long header. Handshake. v4 vip v6 real. Conn Id based."
  },
  //27
  {
    // Ether(src="0x1", dst="0x2")/IP(src="192.168.1.42", dst="10.200.1.5")/UDP(sport=31337, dport=443)/'\xff\xfa\xce\xb0\x01\x08\x44\x01\x03\x04\x05\x06\x07\x00\x00\x01\x11\x01quic data\x00@'
    "AgAAAAAAAQAAAAAACABFAAA5AAEAAEARrRTAqAEqCsgBBXppAbsAJYRt//rOsAEIRAEDBAUGBwAAAREBcXVpYyBkYXRhAEA=",
    "QUIC: long header. Retry. v4 vip v6 real. Conn Id based."
  },
  //28
  {
    // Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::42", dst="fc00:1::2")/UDP(sport=31337, dport=443)/'\xcf\xfa\xce\xb0\x01\x08\x44\x01\x03\x04\x05\x06\x07\x00\x00\x01\x11\x01quic data\x00@'
    "AgAAAAAAAQAAAAAAht1gAAAAACURQPwAAAIAAAAAAAAAAAAAAEL8AAABAAAAAAAAAAAAAAACemkBuwAlicTP+s6wAQhEAQMEBQYHAAABEQFxdWljIGRhdGEAQA==",
    "QUIC: long header. client initial. v6 vip v6 real. LRU miss"
  },
  //29
  {
    // Ether(src="0x1", dst="0x2")/IP(src="192.168.1.42", dst="10.200.1.5")/UDP(sport=31337, dport=443)/'\x00'
    "AgAAAAAAAQAAAAAACABFAAAdAAEAAEARrTDAqAEqCsgBBXppAbsACbYYAA==",
    "QUIC: short header. No connection id. CH. LRU hit"
  },
  //30
  {
    // Ether(src="0x1", dst="0x2")/IP(src="192.168.1.42", dst="10.200.1.5")/UDP(sport=31337, dport=443)/'\x00\x41\x00\x83\x04\x05\x06\x07\x00@'
    "AgAAAAAAAQAAAAAACABFAAAmAAEAAEARrSfAqAEqCsgBBXppAbsAEqr2AEEAgwQFBgcAQA==",
    "QUIC: short header w/ connection id"
  },
  //31
  {
    // Ether(src="0x1", dst="0x2")/IP(src="192.168.1.42", dst="10.200.1.5")/UDP(sport=31337, dport=443)/'\x00\x41\x11\x00\x00\x00\x00\x00\x00@'
    "AgAAAAAAAQAAAAAACABFAAAmAAEAAEARrSfAqAEqCsgBBXppAbsAEqSFAEERAAAAAAAAQA==",
    "QUIC: short header w/ connection id but non-existing mapping"
  },
  //32
  {
    // Ether(src="0x1", dst="0x2")/IP(src="192.168.1.42", dst="10.200.1.5")/UDP(sport=31337, dport=443)/'\x00\x40\x00\x03\x04\x05\x06\x07\x00@'
    "AgAAAAAAAQAAAAAACABFAAAmAAEAAEARrSfAqAEqCsgBBXppAbsAEqt3AEAAAwQFBgcAQA==",
    "QUIC: short header w/ conn id. host id = 0. CH. LRU hit"
  },
};

const std::vector<std::pair<std::string, std::string>> outputTestFixtures = {
  //1
  {
    "AADerb6vAgAAAAAACABFAAA/AAAAAEAEXC2sEGh7CgAAA0UAACsAAQAAQBGtT8CoAQEKyAEBemkAUAAXl95rYXRyYW4gdGVzdCBwa3Q=",
    "XDP_TX"
  },
  //2
  {
    "AADerb6vAgAAAAAACABFAABLAAAAAEAEXCGsEGh7CgAAA0UAADcAAQAAQAatTsCoAQEKyAEBemkAUAAAAAAAAAAAUBAgACfkAABrYXRyYW4gdGVzdCBwa3Q=",
    "XDP_TX"
  },
  //3
  {
    "AADerb6vAgAAAAAACABFjABLAAAAAEAEW5WsEGh7CgAAA0WMADcAAQAAQAaswsCoAQEKyAEBemkAUAAAAAAAAAAAUBAgACfkAABrYXRyYW4gdGVzdCBwa3Q=",
    "XDP_TX"
  },
  //4
  {
    "AADerb6vAgAAAAAACABFAABLAAAAAEAEXCKsEGh7CgAAAkUAADcAAQAAQAatTcCoAQEKyAECemkAKgAAAAAAAAAAUBAgACgJAABrYXRyYW4gdGVzdCBwa3Q=",
    "XDP_TX"
  },
  //5
  {
    "AADerb6vAgAAAAAAht1gAAAAADcEQAEAAAAAAAAAAAAAALrBAQH8AAAAAAAAAAAAAAAAAAABRQAANwABAABABq1MwKgBAQrIAQN6aQBQAAAAAAAAAABQECAAJ+IAAGthdHJhbiB0ZXN0IHBrdA==",
    "XDP_TX"
  },
  //6
  {
    "AADerb6vAgAAAAAAht1gAAAAAEspQAEAAAAAAAAAAAAAAHppAAH8AAAAAAAAAAAAAAAAAAADYAAAAAAjBkD8AAACAAAAAAAAAAAAAAAB/AAAAQAAAAAAAAAAAAAAAXppAFAAAAAAAAAAAFAQIAD9TwAAa2F0cmFuIHRlc3QgcGt0",
    "XDP_TX"
  },
  //7
  {
    "AADerb6vAgAAAAAAht1owAAAAEspQAEAAAAAAAAAAAAAAHppAAH8AAAAAAAAAAAAAAAAAAADaMAAAAAjBkD8AAACAAAAAAAAAAAAAAAB/AAAAQAAAAAAAAAAAAAAAXppAFAAAAAAAAAAAFAQIAD9TwAAa2F0cmFuIHRlc3QgcGt0",
    "XDP_TX"
  },
  //8
  {
    "AQAAAAAAAgAAAAAACABFAAAcAAEAAEABrWwKyAEDwKgBAQAA//8AAAAA",
    "XDP_TX",
  },
  //9
  {
    "AQAAAAAAAgAAAAAAht1gAAAAAAg6QPwAAAEAAAAAAAAAAAAAAAH8AAACAAAAAAAAAAAAAAABgQCGtgAAAAA=",
    "XDP_TX"
  },
  //10
  {
    "AADerb6vAgAAAAAACABFAABnAAAAAEAEXAWsEGh7CgAAA0UAAFMAAQAAQAFKN8CoZAEKyAEBAwTKlwAAAABFAAA3AAEAAEAGrU4KyAEBwKgBAQBQemkAAAAAAAAAAFACIAAZAQAAdGVzdCBrYXRyYW4gcGt0",
    "XDP_TX"
  },
  //11
  {
    "AADerb6vAgAAAAAAht1gAAAAAH4pQAEAAAAAAAAAAAAAAHppAAH8AAAAAAAAAAAAAAAAAAADYAAAAABWOkD8AAIAAAAAAAAAAAAAAAAB/AAAAQAAAAAAAAAAAAAAAQIAmDAAAAUAYAAAAAAmBkD8AAABAAAAAAAAAAAAAAAB/AAAAgAAAAAAAAAAAAAAAQBQemkAAAAAAAAAAFACIACohQAAa2F0cmFuIHRlc3QgcGFja2V0",
    "XDP_TX"
  },
  //12
  {
    "AgAAAAAAAQAAAAAACABGAAA3AAEAAEAGrE7AqAEBCsgBAXppAFAAAAAAAAAAAFAQIAAn5AAAa2F0cmFuIHRlc3QgcGt0",
    "XDP_DROP"
  },
  //13
  {
    "AgAAAAAAAQAAAAAACABFAAA3AAEgAEAGjU7AqAEBCsgBAXppAFAAAAAAAAAAAFAQIAAn5AAAa2F0cmFuIHRlc3QgcGt0",
    "XDP_DROP"
  },
  //14
  {
    "AgAAAAAAAQAAAAAAht1gAAAAACMsQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1PAABrYXRyYW4gdGVzdCBwa3Q=",
    "XDP_DROP"
  },
  //15
  {
    "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGrU7AqAEBCsgBAXppAFIAAAAAAAAAAFAQIAAn4gAAa2F0cmFuIHRlc3QgcGt0",
    "XDP_PASS"
  },
  //16
  {
    "AgAAAAAAAQAAAAAAht1gAAAAACMGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUgAAAAAAAAAAUBAgAP1NAABrYXRyYW4gdGVzdCBwa3Q=",
    "XDP_PASS"
  },
  //17
  {
    "AgAAAAAAAQAAAAAACAYAAQgABgQAAQAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "XDP_PASS"
  },
  //18
  {
    "AADerb6vAgAAAAAACABFAABLAAAAAEAEXCGsEGh7CgAAA0UAADcAAQAAQAatTsCoAQEKyAEBemkAUAAAAAAAAAAAUBAgACfkAABrYXRyYW4gdGVzdCBwa3Q=",
    "XDP_TX"
  },
  //19
  {
    "AADerb6vAgAAAAAACABFAABLAAAAAEAEmp2sECoACgAAAkUAADcAAQAAQAatS8CoAQEKyAEEemkAKgAAAAAAAAAAUBAgACgHAABrYXRyYW4gdGVzdCBwa3Q=",
    "XDP_TX"
  },
  //20
  {
    "AADerb6vAgAAAAAACABFAABLAAAAAEAEmp2sECoACgAAAkUAADcAAQAAQAas6MCoAWQKyAEEBTkAKgAAAAAAAAAAUBAgAJzUAABrYXRyYW4gdGVzdCBwa3Q=",
    "XDP_TX"
  },
  //21
  {
    "AgAAAAAAAQAAAAAACABFAAA/AAEAAEAEvZesEAEBrBBkAUUAACsAAQAAQBGtT8CoAQEKyAEBemkAUAAXl95rYXRyYW4gdGVzdCBwa3Q=",
    "XDP_PASS"

  },
  //22
  {
    "AgAAAAAAAQAAAAAAht1gAAAAAEspQAEAAAAAAAAAAAAAAAAAAAEBAAAAAAAAAAAAAAAAAAACYAAAAAAjBkD8AAACAAAAAAAAAAAAAAAB/AAAAQAAAAAAAAAAAAAAAXppAFAAAAAAAAAAAFAQIAD9TwAAa2F0cmFuIHRlc3QgcGt0",
    "XDP_PASS"
  },
  //23
  {
    "AgAAAAAAAQAAAAAAht1gAAAAACsEQAEAAAAAAAAAAAAAAAAAAAEBAAAAAAAAAAAAAAAAAAACRQAAKwABAABAEa1PwKgBAQrIAQF6aQBQABeX3mthdHJhbiB0ZXN0IHBrdA==",
    "XDP_PASS"
  },
  //24
  {
    "AADerb6vAgAAAAAACABFAABNAAAAAEAEXEusEGhQCgAAAkUAADkAAQAAQBGtFMCoASoKyAEFemkBuwAlt2zP+s6wAQhBAgMEBQYHAAABEQFxdWljIGRhdGEAQA==",
    "XDP_TX"
  },
  //25
  {
    "AADerb6vAgAAAAAACABFAABNAAAAAEAEXEusEGhQCgAAAkUAADkAAQAAQBGtFMCoASoKyAEFemkBuwAls0bf+s6wAQhD/zNEVWZ3iAABEQFxdWljIGRhdGEAQA==",
    "XDP_TX"
  },
  //26
  {
    "AADerb6vAgAAAAAACABFAABNAAAAAEAEXEysEGhQCgAAAUUAADkAAQAAQBGtFMCoASoKyAEFemkBuwAllG3v+s6wAQhEAQMEBQYHAAABEQFxdWljIGRhdGEAQA==",
    "XDP_TX"
  },
  //27
  {
    "AADerb6vAgAAAAAACABFAABNAAAAAEAEXEysEGhQCgAAAUUAADkAAQAAQBGtFMCoASoKyAEFemkBuwAlhG3/+s6wAQhEAQMEBQYHAAABEQFxdWljIGRhdGEAQA==",
    "XDP_TX"
  },
  //28
  {
    "AADerb6vAgAAAAAAht1gAAAAAE0pQAEAAAAAAAAAAAAAAHppAEL8AAAAAAAAAAAAAAAAAAABYAAAAAAlEUD8AAACAAAAAAAAAAAAAABC/AAAAQAAAAAAAAAAAAAAAnppAbsAJYnEz/rOsAEIRAEDBAUGBwAAAREBcXVpYyBkYXRhAEA=",
    "XDP_TX"
  },
  //29
  {
    "AADerb6vAgAAAAAACABFAAAxAAAAAEAEXGesEGhQCgAAAkUAAB0AAQAAQBGtMMCoASoKyAEFemkBuwAJthgA",
    "XDP_TX"
  },
  //30
  {
    "AADerb6vAgAAAAAAht1gAAAAACYEQAEAAAAAAAAAAAAAALrBASr8AAAAAAAAAAAAAAAAAAACRQAAJgABAABAEa0nwKgBKgrIAQV6aQG7ABKq9gBBAIMEBQYHAEA=",
    "XDP_TX"
  },
  //31
  {
    "AADerb6vAgAAAAAACABFAAA6AAAAAEAEXF+sEGhQCgAAAUUAACYAAQAAQBGtJ8CoASoKyAEFemkBuwASpIUAQREAAAAAAABA",
    "XDP_TX"
  },
  //32
  {
    "AADerb6vAgAAAAAACABFAAA6AAAAAEAEXF6sEGhQCgAAAkUAACYAAQAAQBGtJ8CoASoKyAEFemkBuwASq3cAQAADBAUGBwBA",
    "XDP_TX"
  },
};
} // namespace testing
} // namespace katran
