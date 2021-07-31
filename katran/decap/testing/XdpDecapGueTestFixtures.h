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
 * Input packets has been generated with scapy.
 *
 * Format of the input data: <string, string>; 1st string is a base64 encoded
 * packet. 2nd string is test's description
 *
 * Format of the output data: <string, string>; 1st string is a base64 encoded
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
    // Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.1")/UDP(sport=31337, dport=80)/""
    "AgAAAAAAAQAAAAAACABFAAAcAAEAAEARrV7AqAEBCsgBAXppAFAACLey",
    "Empty IPv4 packet"
  },
  //2
  {
    // Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.1")/UDP(sport=31337, dport=80)/"katran test pkt"
    "AgAAAAAAAQAAAAAACABFAAArAAEAAEARrU/AqAEBCsgBAXppAFAAF5fea2F0cmFuIHRlc3QgcGt0",
    "Plain ipv4 packet"
  },
  //3
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1", dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
    "AgAAAAAAAQAAAAAAht1gAAAAACMGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1PAABrYXRyYW4gdGVzdCBwa3Q=",
    "Plain ipv6 packet"
  },
  //4
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.1",ihl=5,flags="MF")/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
    "AgAAAAAAAQAAAAAACABFAAA3AAEgAEAGjU7AqAEBCsgBAXppAFAAAAAAAAAAAFAQIAAn5AAAa2F0cmFuIHRlc3QgcGt0",
    "drop of IPv4 fragmented packet"
  },
  //5
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1", dst="fc00:1::1",nh=44)/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
    "AgAAAAAAAQAAAAAAht1gAAAAACMsQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1PAABrYXRyYW4gdGVzdCBwa3Q=",
    "drop of IPv6 fragmented packet"
  },
  //6
  {
    //Ether(src="0x1", dst="0x2")/IP(src="172.16.1.1", dst="172.16.100.1")/UDP(sport=1337, dport=6080)/IP(src="192.168.1.1", dst="10.200.1.1")/UDP(sport=31337, dport=80)/"katran test pkt"
    "AgAAAAAAAQAAAAAACABFAABHAAEAAEARvYKsEAEBrBBkAQU5F8AAM/MGRQAAKwABAABAEa1PwKgBAQrIAQF6aQBQABeX3mthdHJhbiB0ZXN0IHBrdA==",
    "gue ipv4 inner ipv4 outer packet"

  },
  //7
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="100::1", dst="100::2")/UDP(sport=1337, dport=6080)/IPv6(src="fc00:2::1", dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
    "AgAAAAAAAQAAAAAAht1gAAAAAFMRQAEAAAAAAAAAAAAAAAAAAAEBAAAAAAAAAAAAAAAAAAACBTkXwABTehJgAAAAACMGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1PAABrYXRyYW4gdGVzdCBwa3Q=",
    "gue ipv6 inner ipv6 outer packet"
  },
  //8
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="100::1", dst="100::2")/UDP(sport=1337, dport=6080)/IP(src="192.168.1.1", dst="10.200.1.1")/UDP(sport=31337, dport=80)/"katran test pkt"
    "AgAAAAAAAQAAAAAAht1gAAAAADMRQAEAAAAAAAAAAAAAAAAAAAEBAAAAAAAAAAAAAAAAAAACBTkXwAAzridFAAArAAEAAEARrU/AqAEBCsgBAXppAFAAF5fea2F0cmFuIHRlc3QgcGt0",
    "gue ipv4 inner ipv6 outer packet"
  },
  //9
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="100::1", dst="100::2")/UDP(sport=1337, dport=6080)/IPv6(src="fc00:2::1", dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A")/""
    "AgAAAAAAAQAAAAAAht1gAAAAAFMRQAEAAAAAAAAAAAAAAAAAAAEBAAAAAAAAAAAAAAAAAAACBTkXwABTehJgAAAAACMGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1PAABrYXRyYW4gdGVzdCBwa3Q=",
    "gue ipv6 inner ipv6 outer packet, empty packet content"
  },
  //10
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.3")/ICMP(type="echo-request")
    "AgAAAAAAAQAAAAAACABFAAAcAAEAAEABrWzAqAEBCsgBAwgA9/8AAAAA",
    "v4 ICMP echo-request"
  },
  //11
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1", dst="fc00:1::1")/ICMPv6EchoRequest()
    "AgAAAAAAAQAAAAAAht1gAAAAAAg6QPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABgACHtgAAAAA=",
    "v6 ICMP echo-request"
  },
};

const std::vector<std::pair<std::string, std::string>> outputGueTestFixtures = {
  //1
  {
    "AgAAAAAAAQAAAAAACABFAAAcAAEAAEARrV7AqAEBCsgBAXppAFAACLey",
    "XDP_PASS"
  },
  //2
  {
    "AgAAAAAAAQAAAAAACABFAAArAAEAAEARrU/AqAEBCsgBAXppAFAAF5fea2F0cmFuIHRlc3QgcGt0",
    "XDP_PASS"
  },
  //3
  {
      "AgAAAAAAAQAAAAAAht1gAAAAACMGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1PAABrYXRyYW4gdGVzdCBwa3Q=",
    "XDP_PASS"
  },
  //4
  {
    "AgAAAAAAAQAAAAAACABFAAA3AAEgAEAGjU7AqAEBCsgBAXppAFAAAAAAAAAAAFAQIAAn5AAAa2F0cmFuIHRlc3QgcGt0",
    "XDP_DROP"
  },
  //5
  {
    "AgAAAAAAAQAAAAAAht1gAAAAACMsQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1PAABrYXRyYW4gdGVzdCBwa3Q=",
    "XDP_DROP"
  },
  //6
  {
    "AgAAAAAAAQAAAAAACABFAAArAAEAAEARrU/AqAEBCsgBAXppAFAAF5fea2F0cmFuIHRlc3QgcGt0",
    "XDP_PASS"

  },
  //7
  {
    "AgAAAAAAAQAAAAAAht1gAAAAACMGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1PAABrYXRyYW4gdGVzdCBwa3Q=",
    "XDP_PASS"
  },
  //8
  {
    "AgAAAAAAAQAAAAAACABFAAArAAEAAEARrU/AqAEBCsgBAXppAFAAF5fea2F0cmFuIHRlc3QgcGt0",
    "XDP_PASS"
  },
  //9
  {
    "AgAAAAAAAQAAAAAAht1gAAAAACMGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1PAABrYXRyYW4gdGVzdCBwa3Q=",
    "XDP_PASS"
  },
  //10
  {
    "AgAAAAAAAQAAAAAACABFAAAcAAEAAEABrWzAqAEBCsgBAwgA9/8AAAAA",
    "XDP_PASS"
  },
  //11
  {
    "AgAAAAAAAQAAAAAAht1gAAAAAAg6QPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABgACHtgAAAAA=",
    "XDP_PASS"
  },
};

} // namespace testing
} // namespace katran
