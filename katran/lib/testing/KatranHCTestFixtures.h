// @nolint
/* Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved.
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
#include <bpf/bpf.h>
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

const std::vector<struct __sk_buff> getInputCtxsForHcTest() {
  std::vector<struct __sk_buff> v;
  for (int i = 0; i < 4; i++) {
    struct __sk_buff skb = {};
    skb.mark = i;
    v.push_back(skb);
  }
  return v;
};

const std::vector<PacketAttributes> hcTestFixtures = {
    // 1
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1",
     // dst="10.200.1.1")/UDP(sport=31337, dport=80)/"katran test pkt"
     .inputPacket =
         "AgAAAAAAAQAAAAAACABFAAArAAEAAEARrU/AqAEBCsgBAXppAFAAF5fea2F0cmFuIHRlc3QgcGt0",
     .description = "v4 packet. no fwmark",
     .expectedReturnValue = "TC_ACT_UNSPEC",
     .expectedOutputPacket =
         "AgAAAAAAAQAAAAAACABFAAArAAEAAEARrU/AqAEBCsgBAXppAFAAF5fea2F0cmFuIHRlc3QgcGt0"},
    // 2
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1",
     // dst="10.200.1.1")/UDP(sport=31337, dport=80)/"katran test pkt"
     .inputPacket =
         "AgAAAAAAAQAAAAAACABFAAArAAEAAEARrU/AqAEBCsgBAXppAFAAF5fea2F0cmFuIHRlc3QgcGt0",
     .description = "v4 packet. fwmark 1",
     .expectedReturnValue = "TC_ACT_REDIRECT",
     .expectedOutputPacket =
         "AADerb6vAP/erb6vCABFAAA/AAAAAEAEWZYKAA0lCgAAAUUAACsAAQAAQBGtT8CoAQEKyAEBemkAUAAXl95rYXRyYW4gdGVzdCBwa3Q="},

    // 3
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1",
     // dst="10.200.1.1")/TCP(sport=31337, dport=80, flags="A")/"katran test
     // pkt"
     .inputPacket =
         "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGrU7AqAEBCsgBAXppAFAAAAAAAAAAAFAQIAAn5AAAa2F0cmFuIHRlc3QgcGt0",
     .description = "v4 packet. fwmark 2",
     .expectedReturnValue = "TC_ACT_REDIRECT",
     .expectedOutputPacket =
         "AADerb6vAP/erb6vCABFAABLAAAAAEAEWYkKAA0lCgAAAkUAADcAAQAAQAatTsCoAQEKyAEBemkAUAAAAAAAAAAAUBAgACfkAABrYXRyYW4gdGVzdCBwa3Q="},
    // 4
    {// Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1",
     // dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
     .inputPacket =
         "AgAAAAAAAQAAAAAAht1gAAAAACMGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1PAABrYXRyYW4gdGVzdCBwa3Q=",
     .description = "v6 packet. fwmark 3",
     .expectedReturnValue = "TC_ACT_REDIRECT",
     .expectedOutputPacket =
         "AADerb6vAP/erb6vht1gAAAAAEspQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAABYAAAAAAjBkD8AAACAAAAAAAAAAAAAAAB/AAAAQAAAAAAAAAAAAAAAXppAFAAAAAAAAAAAFAQIAD9TwAAa2F0cmFuIHRlc3QgcGt0"},
};

// Test fixtures for GUE encapsulation
const std::vector<PacketAttributes> hcGueTestFixtures = {
    // 1
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1",
     // dst="10.200.1.1")/UDP(sport=31337, dport=80)/"katran test pkt"
     .inputPacket =
         "AgAAAAAAAQAAAAAACABFAAArAAEAAEARrU/AqAEBCsgBAXppAFAAF5fea2F0cmFuIHRlc3QgcGt0",
     .description = "v4 packet. no fwmark",
     .expectedReturnValue = "TC_ACT_UNSPEC",
     .expectedOutputPacket =
         "AgAAAAAAAQAAAAAACABFAAArAAEAAEARrU/AqAEBCsgBAXppAFAAF5fea2F0cmFuIHRlc3QgcGt0"},
    // 2
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1",
     // dst="10.200.1.1")/UDP(sport=31337, dport=80)/"katran test pkt"
     .inputPacket =
         "AgAAAAAAAQAAAAAACABFAAArAAEAAEARrU/AqAEBCsgBAXppAFAAF5fea2F0cmFuIHRlc3QgcGt0",
     .description = "v4 packet. fwmark 1",
     .expectedReturnValue = "TC_ACT_REDIRECT",
     .expectedOutputPacket =
         "AADerb6vAP/erb6vCABFAABHAAAAAEARWYEKAA0lCgAAAfchJp4AMwAARQAAKwABAABAEa1PwKgBAQrIAQF6aQBQABeX3mthdHJhbiB0ZXN0IHBrdA=="},
    // 3
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1",
     // dst="10.200.1.1")/TCP(sport=31337, dport=80, flags="A")/"katran test
     // pkt"
     .inputPacket =
         "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGrU7AqAEBCsgBAXppAFAAAAAAAAAAAFAQIAAn5AAAa2F0cmFuIHRlc3QgcGt0",
     .description = "v4 packet. fwmark 2",
     .expectedReturnValue = "TC_ACT_REDIRECT",
     .expectedOutputPacket =
         "AADerb6vAP/erb6vCABFAABTAAAAAEARWXQKAA0lCgAAAvchJp4APwAARQAANwABAABABq1OwKgBAQrIAQF6aQBQAAAAAAAAAABQECAAJ+QAAGthdHJhbiB0ZXN0IHBrdA=="},
    // 4
    {// Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1",
     // dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
     .inputPacket =
         "AgAAAAAAAQAAAAAAht1gAAAAACMGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1PAABrYXRyYW4gdGVzdCBwa3Q=",
     .description = "v6 packet. fwmark 3",
     .expectedReturnValue = "TC_ACT_REDIRECT",
     .expectedOutputPacket =
         "AADerb6vAP/erb6vht1gAAAAAFMRQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAAB9yEmngBTAABgAAAAACMGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1PAABrYXRyYW4gdGVzdCBwa3Q="},
};

} // namespace testing
} // namespace katran
