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
 * see KatranTestFixtures.h on how to generate input and output data
 */
using TestFixture = std::vector<PacketAttributes>;
const TestFixture optionalTestFixtures = {
  //1
  {
    // Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.1")/UDP(sport=31337, dport=80)/("katran test pkt"*100)
    .inputPacket = "AgAAAAAAAQAAAAAACABFAAX4AAEAAEARp4LAqAEBCsgBAXppAFAF5Og2a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0",
    .description = "ICMPv4 packet too big. ICMP_TOOBIG_GENERATION and 4.17+ kernel is required",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AQAAAAAAAgAAAAAACABFAABwAAAAAEABrRsKyAEBwKgBAQMEboQAAAXcRQAF+AABAABAEaeCwKgBAQrIAQF6aQBQBeToNmthdHJhbiB0ZXN0IHBrdGthdHJhbiB0ZXN0IHBrdGthdHJhbiB0ZXN0IHBrdGthdHJhbiB0ZXN0"
  },
  //2
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1", dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A")/("katran test pkt"*100)
    .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAABfAGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAFN1AABrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3Q=",
    .description = "ICMPv6 packet too big. ICMP_TOOBIG_GENERATION and 4.17+ kernel is required",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AQAAAAAAAgAAAAAAht1gAAAAAQA6QPwAAAEAAAAAAAAAAAAAAAH8AAACAAAAAAAAAAAAAAABAgD3sgAABdxgAAAABfAGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAFN1AABrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdA=="
  },
  //3
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.1")/UDP(sport=31337, dport=80)/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAACABFAAArAAEAAEARrU/AqAEBCsgBAXppAFAAF5fea2F0cmFuIHRlc3QgcGt0",
    .description = "ipv4: lpm cached flow. LPM_SRC_LOOKUP is required",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAACABFAAA/AAAAAEAEXC2sEGh7CgAAA0UAACsAAQAAQBGtT8CoAQEKyAEBemkAUAAXl95rYXRyYW4gdGVzdCBwa3Q="
  },
  //4
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.2", dst="10.200.1.1")/UDP(sport=31337, dport=80)/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAACABFAAArAAEAAEARrU7AqAECCsgBAXppAFAAF5fda2F0cmFuIHRlc3QgcGt0",
    .description = "ipv4: lpm src lookup /17. LPM_SRC_LOOKUP is required",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAACsEQAEAAAAAAAAAAAAAALrBAQL8AAAAAAAAAAAAAAAjBwABRQAAKwABAABAEa1OwKgBAgrIAQF6aQBQABeX3WthdHJhbiB0ZXN0IHBrdA=="
  },
  //5
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.100.1", dst="10.200.1.1")/UDP(sport=31337, dport=80)/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAACABFAAArAAEAAEARSk/AqGQBCsgBAXppAFAAFzTea2F0cmFuIHRlc3QgcGt0",
    .description = "ipv4: lpm src lookup /24 . LPM_SRC_LOOKUP is required",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAACsEQAEAAAAAAAAAAAAAALrBZAH8AAAAAAAAAAAAAAAjBwACRQAAKwABAABAEUpPwKhkAQrIAQF6aQBQABc03mthdHJhbiB0ZXN0IHBrdA=="
  },
  //6
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.200.1", dst="10.200.1.1")/UDP(sport=31337, dport=80)/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAACABFAAArAAEAAEAR5k7AqMgBCsgBAXppAFAAF9Dda2F0cmFuIHRlc3QgcGt0",
    .description = "ipv4: lpm miss. LPM_SRC_LOOKUP is required",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAACABFAAA/AAAAAEAEIy2sEKF7CgAAA0UAACsAAQAAQBHmTsCoyAEKyAEBemkAUAAX0N1rYXRyYW4gdGVzdCBwa3Q="
  },
  //7
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::2", dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAACMGQPwAAAIAAAAAAAAAAAAAAAL8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1OAABrYXRyYW4gdGVzdCBwa3Q=",
    .description = "ipv6: lpm src lookup /64. LPM_SRC_LOOKUP is required",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAEspQAEAAAAAAAAAAAAAAHppAAL8AAAAAAAAAAAAAAAjBwAQYAAAAAAjBkD8AAACAAAAAAAAAAAAAAAC/AAAAQAAAAAAAAAAAAAAAXppAFAAAAAAAAAAAFAQIAD9TgAAa2F0cmFuIHRlc3QgcGt0"
  },
  //8
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2307::1", dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAACMGQPwAIwcAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgANpKAABrYXRyYW4gdGVzdCBwa3Q=",
    .description = "ipv6: lpm src lookup /32. LPM_SRC_LOOKUP is required",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAEspQAEAAAAAAAAAAAAAAHppAAH8AAAAAAAAAAAAAAAjBwAEYAAAAAAjBkD8ACMHAAAAAAAAAAAAAAAB/AAAAQAAAAAAAAAAAAAAAXppAFAAAAAAAAAAAFAQIADaSgAAa2F0cmFuIHRlc3QgcGt0"
  },
  //9
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2308:1::1", dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAACMGQPwAIwgAAQAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgANpIAABrYXRyYW4gdGVzdCBwa3Q=",
    .description = "ipv6: lpm miss. LPM_SRC_LOOKUP is required",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAEspQAEAAAAAAAAAAAAAAHppAAH8AAAAAAAAAAAAAAAAAAABYAAAAAAjBkD8ACMIAAEAAAAAAAAAAAAB/AAAAQAAAAAAAAAAAAAAAXppAFAAAAAAAAAAAFAQIADaSAAAa2F0cmFuIHRlc3QgcGt0"
  },
  //10
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1", dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAACMGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1PAABrYXRyYW4gdGVzdCBwa3Q=",
    .description = "ipv6: lpm cached flow. LPM_SRC_LOOKUP is required",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAEspQAEAAAAAAAAAAAAAAHppAAH8AAAAAAAAAAAAAAAAAAADYAAAAAAjBkD8AAACAAAAAAAAAAAAAAAB/AAAAQAAAAAAAAAAAAAAAXppAFAAAAAAAAAAAFAQIAD9TwAAa2F0cmFuIHRlc3QgcGt0"
  },
  //11
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="100::64", dst="fc00:1404::1")/IP(src="192.168.1.3", dst="10.200.1.1")/UDP(sport=31337, dport=80)/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAACsEQAEAAAAAAAAAAAAAAAAAAGT8ABQEAAAAAAAAAAAAAAABRQAAKwABAABAEa1NwKgBAwrIAQF6aQBQABeX3GthdHJhbiB0ZXN0IHBrdA==",
    .description = "ip4ip6 inline decap. INLINE_DECAP is required",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAACsEQAEAAAAAAAAAAAAAALrBAQP8AAAAAAAAAAAAAAAjBwABRQAAKwABAAA/Ea5NwKgBAwrIAQF6aQBQABeX3GthdHJhbiB0ZXN0IHBrdA=="
  },
  //12
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="100::64", dst="fc00:1404::1")/IPv6(src="fc00:2307:1::2", dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAAEspQAEAAAAAAAAAAAAAAAAAAGT8ABQEAAAAAAAAAAAAAAABYAAAAAAjBkD8ACMHAAEAAAAAAAAAAAAC/AAAAQAAAAAAAAAAAAAAAXppAFAAAAAAAAAAAFAQIADaSAAAa2F0cmFuIHRlc3QgcGt0",
    .description = "ip6ip6 inline decap. INLINE_DECAP is required",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAEspQAEAAAAAAAAAAAAAAHppAAL8AAAAAAAAAAAAAAAjBwADYAAAAAAjBj/8ACMHAAEAAAAAAAAAAAAC/AAAAQAAAAAAAAAAAAAAAXppAFAAAAAAAAAAAFAQIADaSAAAa2F0cmFuIHRlc3QgcGt0"
  },
  //13
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="100::64", dst="fc00:1404::1")/IP(src="192.168.1.3", dst="10.200.1.1", ttl=1)/UDP(sport=31337, dport=80)/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAACsEQAEAAAAAAAAAAAAAAAAAAGT8ABQEAAAAAAAAAAAAAAABRQAAKwABAAABEexNwKgBAwrIAQF6aQBQABeX3GthdHJhbiB0ZXN0IHBrdA==",
    .description = "ip4ip6 inline decap ttl 1. INLINE_DECAP is required",
    .expectedReturnValue = "XDP_DROP",
    .expectedOutputPacket = "AgAAAAAAAQAAAAAACABFAAArAAEAAAAR7E3AqAEDCsgBAXppAFAAF5fca2F0cmFuIHRlc3QgcGt0"
  },
  //14
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="100::64", dst="fc00:1404::1")/IPv6(src="fc00:2307:1::2", dst="fc00:1::1", hlim=1)/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAAEspQAEAAAAAAAAAAAAAAAAAAGT8ABQEAAAAAAAAAAAAAAABYAAAAAAjBgH8ACMHAAEAAAAAAAAAAAAC/AAAAQAAAAAAAAAAAAAAAXppAFAAAAAAAAAAAFAQIADaSAAAa2F0cmFuIHRlc3QgcGt0",
    .description = "ip6ip6 inline decap ttl 1. INLINE_DECAP is required",
    .expectedReturnValue = "XDP_DROP",
    .expectedOutputPacket = "AgAAAAAAAQAAAAAAht1gAAAAACMGAPwAIwcAAQAAAAAAAAAAAAL8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgANpIAABrYXRyYW4gdGVzdCBwa3Q="
  },
  //15
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="100::64", dst="fc00:1404::2")/IP(src="192.168.1.3", dst="10.200.1.1")/UDP(sport=31337, dport=80)/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAACsEQAEAAAAAAAAAAAAAAAAAAGT8ABQEAAAAAAAAAAAAAAACRQAAKwABAABAEa1NwKgBAwrIAQF6aQBQABeX3GthdHJhbiB0ZXN0IHBrdA==",
    .description = "ip4ip6 dst is not decap VIP. INLINE_DECAP is required",
    .expectedReturnValue = "XDP_PASS",
    .expectedOutputPacket = "AgAAAAAAAQAAAAAACABFAAArAAEAAD8Rrk3AqAEDCsgBAXppAFAAF5fca2F0cmFuIHRlc3QgcGt0"
  },
  //16
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="100::64", dst="fc00:1404::2")/IPv6(src="fc00:2307:1::2", dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAAEspQAEAAAAAAAAAAAAAAAAAAGT8ABQEAAAAAAAAAAAAAAACYAAAAAAjBkD8ACMHAAEAAAAAAAAAAAAC/AAAAQAAAAAAAAAAAAAAAXppAFAAAAAAAAAAAFAQIADaSAAAa2F0cmFuIHRlc3QgcGt0",
    .description = "ip6ip6 dst is not decap VIP. INLINE_DECAP is required",
    .expectedReturnValue = "XDP_PASS",
    .expectedOutputPacket = "AgAAAAAAAQAAAAAAht1gAAAAACMGP/wAIwcAAQAAAAAAAAAAAAL8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgANpIAABrYXRyYW4gdGVzdCBwa3Q="
  },
  //17
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.6",dst="10.200.1.6")/UDP(sport=31337, dport=80)/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAACABFAAArAAEAAEARrUXAqAEGCsgBBnppAFAAF5fUa2F0cmFuIHRlc3QgcGt0",
    .description = "pass local traffic. LOCAL_DELIVERY_OPTIMIZATION is required",
    .expectedReturnValue = "XDP_PASS",
    .expectedOutputPacket = "AgAAAAAAAQAAAAAACABFAAArAAEAAEARrUXAqAEGCsgBBnppAFAAF5fUa2F0cmFuIHRlc3QgcGt0"
  },
};

}
}
