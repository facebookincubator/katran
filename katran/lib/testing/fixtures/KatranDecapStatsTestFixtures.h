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
#include <bpf/bpf.h>
#include <katran/lib/testing/tools/PacketAttributes.h>
#include <string>
#include <utility>
#include <vector>

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

const std::vector<PacketAttributes> DecapTestFixtures = {
    // gue ip6 in ip6 inline decap. out dst is host primary addr fc00:2307::1337
    {// Ether(src="0x1", dst="0x2")/IPv6(src="100::64",dst="fc00:2307::1337")/UDP(sport=31337,dport=9886)/IPv6(src="fc00:2307:1::2", dst="fc00:1::1")/TCP(sport=31337,dport=80,flags="A")/"katran test pkt"
     .inputPacket =
         "AgAAAAAAAQAAAAAAht1gAAAAAFMRQAEAAAAAAAAAAAAAAAAAAGT8ACMHAAAAAAAAAAAAABM3emkmngBTxGNgAAAAACMGQPwAIwcAAQAAAAAAAAAAAAL8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgANpIAABrYXRyYW4gdGVzdCBwa3Q=",
     .description = "gue ip6ip6 inline decap. INLINE_DECAP_GUE is required",
     .expectedReturnValue = "XDP_PASS",
     .expectedOutputPacket =
         "AgAAAAAAAQAAAAAAht1gAAAAACMGP/wAIwcAAQAAAAAAAAAAAAL8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgANpIAABrYXRyYW4gdGVzdCBwa3Q="},
    // gue ip4 in ip6 inline decap. out dst is host primary addr fc00:2307::1337
    {// Ether(src="0x1", dst="0x2")/IPv6(src="100::64",dst="fc00:2307::1337")/UDP(sport=31337,dport=9886)/IP(src="192.168.1.3", dst="10.200.1.1")/UDP(sport=31337,dport=80)/"katran test pkt"
     .inputPacket =
         "AgAAAAAAAQAAAAAAht1gAAAAADMRQAEAAAAAAAAAAAAAAAAAAGT8ACMHAAAAAAAAAAAAABM3emkmngAz+HpFAAArAAEAAEARrU3AqAEDCsgBAXppAFAAF5fca2F0cmFuIHRlc3QgcGt0",
     .description = "gue ip4 in ip6 inline decap. INLINE_DECAP_GUE is required",
     .expectedReturnValue = "XDP_PASS",
     // Ether(src="0x1", dst="0x2")/IP(src="192.168.1.3",dst="10.200.1.1")/UDP(sport=31337, dport=80)/"katran test pkt"
     .expectedOutputPacket =
         "AgAAAAAAAQAAAAAACABFAAArAAEAAD8Rrk3AqAEDCsgBAXppAFAAF5fca2F0cmFuIHRlc3QgcGt0"},
    // ip6 packet for vip - this should not get decaped, so won't be added to decap vip stats
    {// Ether(src="0x1", dst="0x2")/IPv6(src="100::64",dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
     .inputPacket =
         "AgAAAAAAAQAAAAAAht1gAAAAACMGQAEAAAAAAAAAAAAAAAAAAGT8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAPfvAABrYXRyYW4gdGVzdCBwa3Q=",
     .description = "vip traffic",
     .expectedReturnValue = "XDP_TX",
     // Ether(dst="00:00:de:ad:be:af",src="02:00:00:00:00:00")/IPv6(src="fc00:2307::1337",dst="fc00::2")/UDP(sport=31337, dport=9886)/IPv6(src="100::64",dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
     .expectedOutputPacket =
         "AADerb6vAgAAAAAAht1gAAAAAFMRQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAACemkmngBTycRgAAAAACMGQAEAAAAAAAAAAAAAAAAAAGT8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAPfvAABrYXRyYW4gdGVzdCBwa3Q="},

};

} // namespace testing
} // namespace katran
