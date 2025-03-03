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
 * to get base64 packet string: base64.b64encode(raw(packet))
 * to get packet from base64 string: Ether(base64.b64decode(b"..."))
 *
 * Note: INLINE_DECAP_GUE is required for all tests.
 */
const std::vector<::katran::PacketAttributes> xPopDecapTestFixtures = {
  //1
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="100::64", dst="fc00:1404::1")/UDP(sport=31337, dport=9886)/IP(src="192.168.1.3", dst="10.200.1.1")/UDP(sport=31337, dport=80)/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAADMRQAEAAAAAAAAAAAAAAAAAAGT8ABQEAAAAAAAAAAAAAAABemkmngAzGrRFAAArAAEAAEARrU3AqAEDCsgBAXppAFAAF5fca2F0cmFuIHRlc3QgcGt0",
    .description = "Xpop decap and re-encap: IPv6 decap VIP, IPv4 dst VIP with IPv4 backends",
    .expectedReturnValue = "XDP_TX",
    ///<Ether  dst=00:00:de:ad:be:af src=02:00:00:00:00:00 type=IPv4 |<IP  version=4 ihl=5 tos=0x0 len=71 id=0 flags= frag=0 ttl=64 proto=udp chksum=0x5980 src=10.0.13.37 dst=10.0.0.2 |<UDP  sport=26745 dport=9886 len=51 chksum=0x1ce7 |<Raw  load=
    .expectedOutputPacket = "AADerb6vAgAAAAAACABFAABHAAAAAEARWYAKAA0lCgAAAmh5Jp4AMxznRQAAKwABAAA/Ea5NwKgBAwrIAQF6aQBQABeX3GthdHJhbiB0ZXN0IHBrdA=="
  },
  //2
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="100::64", dst="fc00:1404::1")/UDP(sport=31337, dport=9886)/IP(src="192.168.1.3", dst="10.200.1.2")/UDP(sport=31337, dport=80)/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAADMRQAEAAAAAAAAAAAAAAAAAAGT8ABQEAAAAAAAAAAAAAAABemkmngAzGrVFAAArAAEAAEARrUzAqAEDCsgBAnppAFAAF5fba2F0cmFuIHRlc3QgcGt0",
    .description = "Xpop decap and re-encap: IPv6 decap VIP, IPv4 dst VIP with IPv6 backends",
    .expectedReturnValue = "XDP_TX",
    //<Ether  dst=00:00:de:ad:be:af src=02:00:00:00:00:00 type=IPv6 |<IPv6  version=6 tc=0 fl=0 plen=51 nh=UDP hlim=64 src=fc00:2307::1337 dst=fc00::3 |<UDP  sport=31594 dport=9886 len=51 chksum=0xfcda |<Raw  load=
    .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAADMRQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAADe2omngAz/NpFAAArAAEAAD8RrkzAqAEDCsgBAnppAFAAF5fba2F0cmFuIHRlc3QgcGt0"
  },
  //3
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="100::64", dst="fc00:1404::1")/UDP(sport=31337, dport=9886)/IPv6(src="fc00:2307:1::2", dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAAFMRQAEAAAAAAAAAAAAAAAAAAGT8ABQEAAAAAAAAAAAAAAABemkmngBT5pxgAAAAACMGQPwAIwcAAQAAAAAAAAAAAAL8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgANpIAABrYXRyYW4gdGVzdCBwa3Q=",
    .description = "Xpop decap and re-encap: IPv6 decap VIP, IPv6 dst VIP with TCP payload",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAFMRQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAABemkmngBTycZgAAAAACMGP/wAIwcAAQAAAAAAAAAAAAL8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgANpIAABrYXRyYW4gdGVzdCBwa3Q="
    //<Ether  dst=00:00:de:ad:be:af src=02:00:00:00:00:00 type=IPv6 |<IPv6  version=6 tc=0 fl=0 plen=83 nh=UDP hlim=64 src=fc00:2307::1337 dst=fc00::1 |<UDP  sport=31337 dport=9886 len=83 chksum=0xc9c6
  },
  //4
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="100::64", dst="fc00:1404::1")/UDP(sport=31337, dport=9886)/IP(src="192.168.1.3", dst="10.200.1.1", ttl=1)/UDP(sport=31337, dport=80)/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAADMRQAEAAAAAAAAAAAAAAAAAAGT8ABQEAAAAAAAAAAAAAAABemkmngAzGrRFAAArAAEAAAER7E3AqAEDCsgBAXppAFAAF5fca2F0cmFuIHRlc3QgcGt0",
    .description = "Xpop decap and drop: IPv6 decap VIP, IPv4 dst VIP with TTL expired",
    .expectedReturnValue = "XDP_DROP",
    .expectedOutputPacket = "AgAAAAAAAQAAAAAACABFAAArAAEAAAAR7E3AqAEDCsgBAXppAFAAF5fca2F0cmFuIHRlc3QgcGt0"
  },
  //5
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="100::64", dst="fc00:1404::1")/UDP(sport=31337, dport=9886)/IPv6(src="fc00:2307:1::2", dst="fc00:1::1", hlim=1)/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAAFMRQAEAAAAAAAAAAAAAAAAAAGT8ABQEAAAAAAAAAAAAAAABemkmngBT5ttgAAAAACMGAfwAIwcAAQAAAAAAAAAAAAL8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgANpIAABrYXRyYW4gdGVzdCBwa3Q=",
    .description = "Xpop decap and drop: IPv6 decap VIP, IPv6 dst VIP with hop limit expired",
    .expectedReturnValue = "XDP_DROP",
    .expectedOutputPacket = "AgAAAAAAAQAAAAAAht1gAAAAACMGAPwAIwcAAQAAAAAAAAAAAAL8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgANpIAABrYXRyYW4gdGVzdCBwa3Q="
  },
  //6
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="100::64", dst="fc00:2307::1337")/UDP(sport=31337, dport=9886)/IPv6(src="fc00:2307:1::2", dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAAFMRQAEAAAAAAAAAAAAAAAAAAGT8ACMHAAAAAAAAAAAAABM3emkmngBTxGNgAAAAACMGQPwAIwcAAQAAAAAAAAAAAAL8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgANpIAABrYXRyYW4gdGVzdCBwa3Q=",
    .description = "Gue encap and pass: strict inline decap address match with IPv6 dst VIP",
    .expectedReturnValue = "XDP_PASS",
    .expectedOutputPacket = "AgAAAAAAAQAAAAAAht1gAAAAACMGP/wAIwcAAQAAAAAAAAAAAAL8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgANpIAABrYXRyYW4gdGVzdCBwa3Q="
    //<Ether  dst=02:00:00:00:00:00 src=01:00:00:00:00:00 type=IPv6 |<IPv6  version=6 tc=0 fl=0 plen=35 nh=TCP hlim=63 src=fc00:2307:1::2 dst=fc00:1::1 |<TCP  sport=31337 dport=http seq=0 ack=0 dataofs=5 reserved=0 flags=A window=8192 chksum=0xda48 urgptr=0 |<Raw  load='katran test pkt' |>>>>
  },
  //7
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="100::64", dst="fc00::1")/UDP(sport=31337, dport=9886)/IPv6(src="fc00:2307:1::2", dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAAFMRQAEAAAAAAAAAAAAAAAAAAGT8AAAAAAAAAAAAAAAAAAABemkmngBT+qBgAAAAACMGQPwAIwcAAQAAAAAAAAAAAAL8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgANpIAABrYXRyYW4gdGVzdCBwa3Q=",
    .description = "Gue encap and pass: strict inline decap with address mismatch, IPv6 dst VIP, passed as-is to kernel",
    .expectedReturnValue = "XDP_PASS",
    .expectedOutputPacket = "AgAAAAAAAQAAAAAAht1gAAAAAFMRQAEAAAAAAAAAAAAAAAAAAGT8AAAAAAAAAAAAAAAAAAABemkmngBT+qBgAAAAACMGQPwAIwcAAQAAAAAAAAAAAAL8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgANpIAABrYXRyYW4gdGVzdCBwa3Q="
    //<Ether  dst=02:00:00:00:00:00 src=01:00:00:00:00:00 type=IPv6 |<IPv6  version=6 tc=0 fl=0 plen=35 nh=TCP hlim=63 src=fc00:2307:1::2 dst=fc00:1::1 |<TCP  sport=31337 dport=http seq=0 ack=0 dataofs=5 reserved=0 flags=A window=8192 chksum=0xda48 urgptr=0 |<Raw  load='katran test pkt' |>>>>
  },
};
}
}
