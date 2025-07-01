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
#include <vector>
#include "katran/lib/testing/PacketAttributes.h"

namespace katran {
namespace testing {
/**
 * Input packets have been generated with scapy. Above each of them you can find
 * a command which has been used to do so.
 *
 * Format of the input data: <string, string>; 1st string is a base64 encoded
 * packet. 2nd string is test's description
 *
 * Format of the output data: <string, string>; 1st string is a base64 encoded
 * packet which we are expecting to see after bpf program's run.
 * 2nd string = bpf's program return code.
 *
 * To create pcap w/ scapy:
 * 1) create packets
 * 2) pckts = [ <created packets from above> ]
 * 3) wrpcap(<path_to_file>, pckts)
 * To get base64 packet string: base64.b64encode(raw(packet))
 * To get packet from base64 string: Ether(base64.b64decode(b"..."))
 *
 * Note: The test packets below need to be generated with the correct hex values.
 * The comments show the scapy commands that would generate similar packets,
 * but the actual base64 strings need to be filled in with real packet captures.
 */
const std::vector<::katran::PacketAttributes> udpFlowMigrationTestFirstFixtures = {
  // 1. UDP packet to a VIP with flow migration enabled
  {
    // Ether(src="0x1", dst="0x2")/IP(src="10.0.0.1", dst="10.200.1.1")/UDP(sport=31337, dport=80)/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAACABFAAArAAEAAEARZPgKAAABCsgBAXppAFAAF0+Ha2F0cmFuIHRlc3QgcGt0",
    .description = "UDP packet to a VIP with flow migration enabled",
    .expectedReturnValue = "XDP_TX",
    // Ether(dst='00:00:de:ad:be:af', src='02:00:00:00:00:00', type=2048)/IP(version=4, ihl=5, tos=0, len=71, id=0, flags=0, frag=0, ttl=64, proto=17, chksum=22912, src='10.0.13.37', dst='10.0.0.2')/UDP(sport=27003, dport=9886, len=51, chksum=25658)/Raw(load=b'E\\x00\\x00+\\x00\\x01\\x00\\x00@\\x11d\\xf8\\n\\x00\\x00\\x01\\n\\xc8\\x01\\x01zi\\x00P\\x00\\x17O\\x87katran test pkt')
    .expectedOutputPacket = "AADerb6vAgAAAAAACABFAABHAAAAAEARWYAKAA0lCgAAAml7Jp4AM2Q6RQAAKwABAABAEWT4CgAAAQrIAQF6aQBQABdPh2thdHJhbiB0ZXN0IHBrdA=="
  },

  // 2. UDP packet to a udp stable routing VIP  with flow migration enabled
  {
    // Ether(src="0x1", dst="0x2")/IP(src="10.0.0.1", dst="10.200.1.2")/UDP(sport=31337, dport=80)/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAACABFAAArAAEAAEARZPcKAAABCsgBAnppAFAAF0+Ga2F0cmFuIHRlc3QgcGt0",
    .description = "UDP packet to a udp stable routing VIP  with flow migration enabled",
    .expectedReturnValue = "XDP_TX",
    // Ether(dst='00:00:de:ad:be:af', src='02:00:00:00:00:00', type=2048)/IP(version=4, ihl=5, tos=0, len=71, id=0, flags=0, frag=0, ttl=64, proto=17, chksum=22912, src='10.0.13.37', dst='10.0.0.2')/UDP(sport=27003, dport=9886, len=51, chksum=25659)/Raw(load=b'E\\x00\\x00+\\x00\\x01\\x00\\x00@\\x11d\\xf7\\n\\x00\\x00\\x01\\n\\xc8\\x01\\x02zi\\x00P\\x00\\x17O\\x86katran test pkt')
    .expectedOutputPacket = "AADerb6vAgAAAAAACABFAABHAAAAAEARWYAKAA0lCgAAAml7Jp4AM2Q7RQAAKwABAABAEWT3CgAAAQrIAQJ6aQBQABdPhmthdHJhbiB0ZXN0IHBrdA=="
  },

  // 3. UDP packet to a UDP VIP no flow migration
  {
    // Ether(src="0x1", dst="0x2")/IP(src="10.0.0.1", dst="10.200.1.3")/UDP(sport=31337, dport=80)/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAACABFAAArAAEAAEARZPYKAAABCsgBA3ppAFAAF0+Fa2F0cmFuIHRlc3QgcGt0",
    .description = "UDP packet to a UDP VIP no flow migration",
    .expectedReturnValue = "XDP_TX",
    // Ether(dst='00:00:de:ad:be:af', src='02:00:00:00:00:00', type=2048)/IP(version=4, ihl=5, tos=0, len=71, id=0, flags=0, frag=0, ttl=64, proto=17, chksum=22912, src='10.0.13.37', dst='10.0.0.2')/UDP(sport=27003, dport=9886, len=51, chksum=25660)/Raw(load=b'E\\x00\\x00+\\x00\\x01\\x00\\x00@\\x11d\\xf6\\n\\x00\\x00\\x01\\n\\xc8\\x01\\x03zi\\x00P\\x00\\x17O\\x85katran test pkt')
    .expectedOutputPacket = "AADerb6vAgAAAAAACABFAABHAAAAAEARWYAKAA0lCgAAAml7Jp4AM2Q8RQAAKwABAABAEWT2CgAAAQrIAQN6aQBQABdPhWthdHJhbiB0ZXN0IHBrdA=="
  },

  // 4. TCP packet to a TCP vip
  {
    // Ether(src="0x1", dst="0x2")/IP(src="10.0.0.1", dst="10.200.1.4")/TCP(sport=31337, dport=80)/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGZPQKAAABCsgBBHppAFAAAAAAAAAAAFACIADflwAAa2F0cmFuIHRlc3QgcGt0",
    .description = "TCP packet to a TCP vip",
    .expectedReturnValue = "XDP_TX",
    // Ether(dst='00:00:de:ad:be:af', src='02:00:00:00:00:00', type=2048)/IP(version=4, ihl=5, tos=0, len=83, id=0, flags=0, frag=0, ttl=64, proto=17, chksum=22900, src='10.0.13.37', dst='10.0.0.2')/UDP(sport=27003, dport=9886, len=63, chksum=25638)/Raw(load=b'E\\x00\\x007\\x00\\x01\\x00\\x00@\\x06d\\xf4\\n\\x00\\x00\\x01\\n\\xc8\\x01\\x04zi\\x00P\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00P\\x02 \\x00\\xdf\\x97\\x00\\x00katran test pkt')
    .expectedOutputPacket = "AADerb6vAgAAAAAACABFAABTAAAAAEARWXQKAA0lCgAAAml7Jp4AP2QmRQAANwABAABABmT0CgAAAQrIAQR6aQBQAAAAAAAAAABQAiAA35cAAGthdHJhbiB0ZXN0IHBrdA=="
  },

};

const std::vector<::katran::PacketAttributes> udpFlowMigrationTestSecondFixtures = {
  // 1. UDP packet to a VIP with flow migration enabled
  {
    // Ether(src="0x1", dst="0x2")/IP(src="10.0.0.1", dst="10.200.1.1")/UDP(sport=31337, dport=80)/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAACABFAAArAAEAAEARZPgKAAABCsgBAXppAFAAF0+Ha2F0cmFuIHRlc3QgcGt0",
    .description = "UDP packet to a VIP with flow migration enabled - new backend as it was redirected",
    .expectedReturnValue = "XDP_TX",
    // Ether(dst='00:00:de:ad:be:af', src='02:00:00:00:00:00', type=34525)/IPv6(version=6, tc=0, fl=0, plen=51, nh=17, hlim=64, src='fc00:2307::1337', dst='fc00::2')/UDP(sport=31336, dport=9886, len=51, chksum=17970)/Raw(load=b'E\\x00\\x00+\\x00\\x01\\x00\\x00@\\x11d\\xf8\\n\\x00\\x00\\x01\\n\\xc8\\x01\\x01zi\\x00P\\x00\\x17O\\x87katran test pkt')
    .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAADMRQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAACemgmngAzRjJFAAArAAEAAEARZPgKAAABCsgBAXppAFAAF0+Ha2F0cmFuIHRlc3QgcGt0"
  },

  // 2. UDP packet to a udp stable routing VIP  with flow migration enabled
  {
    // Ether(src="0x1", dst="0x2")/IP(src="10.0.0.1", dst="10.200.1.2")/UDP(sport=31337, dport=80)/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAACABFAAArAAEAAEARZPcKAAABCsgBAnppAFAAF0+Ga2F0cmFuIHRlc3QgcGt0",
    .description = "UDP packet to a udp stable routing VIP  with flow migration enabled - new backend as it was redirected",
    .expectedReturnValue = "XDP_TX",
    // Ether(dst='00:00:de:ad:be:af', src='02:00:00:00:00:00', type=34525)/IPv6(version=6, tc=0, fl=0, plen=51, nh=17, hlim=64, src='fc00:2307::1337', dst='fc00::2')/UDP(sport=31336, dport=9886, len=51, chksum=17971)/Raw(load=b'E\\x00\\x00+\\x00\\x01\\x00\\x00@\\x11d\\xf7\\n\\x00\\x00\\x01\\n\\xc8\\x01\\x02zi\\x00P\\x00\\x17O\\x86katran test pkt')
    .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAADMRQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAACemgmngAzRjNFAAArAAEAAEARZPcKAAABCsgBAnppAFAAF0+Ga2F0cmFuIHRlc3QgcGt0"
  },

  // 3. UDP packet to a UDP VIP no flow migration
  {
    // Ether(src="0x1", dst="0x2")/IP(src="10.0.0.1", dst="10.200.1.3")/UDP(sport=31337, dport=80)/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAACABFAAArAAEAAEARZPYKAAABCsgBA3ppAFAAF0+Fa2F0cmFuIHRlc3QgcGt0",
    .description = "UDP packet to a UDP VIP no flow migration",
    .expectedReturnValue = "XDP_TX",
    // Ether(dst='00:00:de:ad:be:af', src='02:00:00:00:00:00', type=2048)/IP(version=4, ihl=5, tos=0, len=71, id=0, flags=0, frag=0, ttl=64, proto=17, chksum=22912, src='10.0.13.37', dst='10.0.0.2')/UDP(sport=27003, dport=9886, len=51, chksum=25660)/Raw(load=b'E\\x00\\x00+\\x00\\x01\\x00\\x00@\\x11d\\xf6\\n\\x00\\x00\\x01\\n\\xc8\\x01\\x03zi\\x00P\\x00\\x17O\\x85katran test pkt')
    .expectedOutputPacket = "AADerb6vAgAAAAAACABFAABHAAAAAEARWYAKAA0lCgAAAml7Jp4AM2Q8RQAAKwABAABAEWT2CgAAAQrIAQN6aQBQABdPhWthdHJhbiB0ZXN0IHBrdA=="
  },

  // 4. TCP packet to a TCP vip
  {
    // Ether(src="0x1", dst="0x2")/IP(src="10.0.0.1", dst="10.200.1.4")/TCP(sport=31337, dport=80)/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGZPQKAAABCsgBBHppAFAAAAAAAAAAAFACIADflwAAa2F0cmFuIHRlc3QgcGt0",
    .description = "TCP packet to a TCP vip",
    .expectedReturnValue = "XDP_TX",
    // Ether(dst='00:00:de:ad:be:af', src='02:00:00:00:00:00', type=2048)/IP(version=4, ihl=5, tos=0, len=83, id=0, flags=0, frag=0, ttl=64, proto=17, chksum=22900, src='10.0.13.37', dst='10.0.0.2')/UDP(sport=27003, dport=9886, len=63, chksum=25638)/Raw(load=b'E\\x00\\x007\\x00\\x01\\x00\\x00@\\x06d\\xf4\\n\\x00\\x00\\x01\\n\\xc8\\x01\\x04zi\\x00P\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00P\\x02 \\x00\\xdf\\x97\\x00\\x00katran test pkt')
    .expectedOutputPacket = "AADerb6vAgAAAAAACABFAABTAAAAAEARWXQKAA0lCgAAAml7Jp4AP2QmRQAANwABAABABmT0CgAAAQrIAQR6aQBQAAAAAAAAAABQAiAA35cAAGthdHJhbiB0ZXN0IHBrdA=="
  },

};

}
}
