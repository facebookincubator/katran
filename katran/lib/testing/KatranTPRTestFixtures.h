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
 * 1) create packets (obtain base64 encoding as: str(pkt).encode("base64"))
 * 2) pckts = [ <created packets from above> ]
 * 3) wrpcap(<path_to_file>, pckts)
 */
const std::vector<PacketAttributes> tprTestFixtures = {
    // 1
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1",
     // dst="10.200.1.1")/TCP(sport=31337, dport=80, flags="S", options=[(0xb7,
     // '\x13\x00\x00\x00'),('NOP', 0),('NOP', 0)])/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAACABFAAA/AAEAAEAGrUbAqAEBCsgBAXppAFAAAAAAAAAAAHACIAA84gAAtwYTAAAAAQFrYXRyYW4gdGVzdCBwa3Q=",
     .description = "V4 VIP (and v4 real), SYN, TPR id ignored",
     .expectedReturnValue = "XDP_TX",
     // "Ether(src='x02', dst='0xdeadbeaf')/IP(src='172.16.104.123',
     // dst='10.0.0.3'/IP(src='192.168.1.1', dst='10.200.1.1'/TCP(dport=80,
     // sport=31337, flags=2L, options=[(183, '\\x13\\x00\\x00\\x00'), ('NOP',
     // None), ('NOP', None)])/Raw(load='katran test pkt')"
     .expectedOutputPacket = "AADerb6vAgAAAAAACABFAABTAAAAAEAEXBmsEGh7CgAAA0UAAD8AAQAAQAatRsCoAQEKyAEBemkAUAAAAAAAAAAAcAIgADziAAC3BhMAAAABAWthdHJhbiB0ZXN0IHBrdA=="
    },
    // 2
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1",
     // dst="10.200.1.1")/TCP(sport=31337, dport=80, flags="A", options=[(0xb7,
     // '\x01\x04\x00\x00'),('NOP', 0),('NOP', 0)])/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAACABFAAA/AAEAAEAGrUbAqAEBCsgBAXppAFAAAAAAAAAAAHAQIABO0AAAtwYBBAAAAQFrYXRyYW4gdGVzdCBwa3Q=",
     .description = "V4 VIP (and v4 real), TPR Id: 1025",
     .expectedReturnValue = "XDP_TX",
     // "Ether(src='x02', dst='0xdeadbeaf')/IP(src='172.16.104.123',
     // dst='10.0.0.3'/IP(src='192.168.1.1', dst='10.200.1.1'/TCP(dport=80,
     // sport=31337, flags=16L, options=[(183, '\\x01\\x04\\x00\\x00'), ('NOP',
     // None), ('NOP', None)])/Raw(load='katran test pkt')"
     .expectedOutputPacket = "AADerb6vAgAAAAAACABFAABTAAAAAEAEXBmsEGh7CgAAA0UAAD8AAQAAQAatRsCoAQEKyAEBemkAUAAAAAAAAAAAcBAgAE7QAAC3BgEEAAABAWthdHJhbiB0ZXN0IHBrdA=="
    },
    // 3
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1",
     // dst="10.200.1.2")/TCP(sport=31337, dport=42, flags="A", options=[(0xb7,
     // '\xff\x03\x00\x00')])/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAACABFAAA/AAEAAEAGrUXAqAEBCsgBAnppACoAAAAAAAAAAHAQIABR9gAAtwb/AwAAAABrYXRyYW4gdGVzdCBwa3Q=",
     .description = "V4 VIP (and v4 real; any dst ports), TPR Id: 1023",
     .expectedReturnValue = "XDP_TX",
     // "Ether(src='x02', dst='0xdeadbeaf')/IP(src='172.16.104.123',
     // dst='10.0.0.2')/IP(src='192.168.1.1', dst='10.200.1.2')/TCP(flags=16L,
     // dport=42, sport=31337, options=[(183, '\\xff\\x03\\x00\\x00'), ('EOL',
     // None)])/Raw(load='katran test pkt')"
     .expectedOutputPacket = "AADerb6vAgAAAAAACABFAABTAAAAAEAEXBqsEGh7CgAAAkUAAD8AAQAAQAatRcCoAQEKyAECemkAKgAAAAAAAAAAcBAgAFH2AAC3Bv8DAAAAAGthdHJhbiB0ZXN0IHBrdA=="
    },
    // 4
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1",
     // dst="10.200.1.3")/TCP(sport=31337, dport=80, flags="A", options=[('NOP',
     // 0),('NOP', 0),('NOP', 0),('NOP', 0),(0xB7, '\x00\x04\x00\x00')])/"katran
     // test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAACABFAABDAAEAAEAGrUDAqAEBCsgBA3ppAFAAAAAAAAAAAIAQIABAyQAAAQEBAbcGAgQAAAAAa2F0cmFuIHRlc3QgcGt0",
     .description = "V4 VIP (and v6 real), TPR Id: 1026.",
     .expectedReturnValue = "XDP_TX",
     // "Ether(src='x02', dst='0xdeadbeaf')/IPv6(src='100::bac1:101',
     // dst='fc00::1')/IP(src='192.168.1.1', dst='10.200.1.3')/TCP(flags=16L,
     // dport=80, sport=31337, options=[('NOP', None), ('NOP', None), ('NOP',
     // None), ('NOP', None), (183, '\\x00\\x04\\x00\\x00'), ('EOL',
     // None)])/Raw(load='katran test pkt')"
     .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAEMEQAEAAAAAAAAAAAAAALrBAQH8AAAAAAAAAAAAAAAAAAACRQAAQwABAABABq1AwKgBAQrIAQN6aQBQAAAAAAAAAACAECAAQMkAAAEBAQG3BgIEAAAAAGthdHJhbiB0ZXN0IHBrdA=="
    },
    // 5
    {// Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1",
     // dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A",
     // options=[(0xB7,'\x00\x04\x00\x00')])/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAACsGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAcBAgACY9AAC3BgAEAAAAAGthdHJhbiB0ZXN0IHBrdA==",
     .description = "V6 VIP (and v6 real), TPR Id: 1024",
     .expectedReturnValue = "XDP_TX",
     // "Ether(src='x02', dst='0xdeadbeaf')/IPv6(src='100::7a69:1',
     // dst='fc00::1')/IPv6(src='fc00:2::1', dst='fc00:1::1')/TCP(flags=16L,
     // dport=80, sport=31337, options=[(183, '\\x00\\x04\\x00\\x00'), ('EOL',
     // None)])/Raw(load='katran test pkt')"
     .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAFMpQAEAAAAAAAAAAAAAAHppAAH8AAAAAAAAAAAAAAAAAAABYAAAAAArBkD8AAACAAAAAAAAAAAAAAAB/AAAAQAAAAAAAAAAAAAAAXppAFAAAAAAAAAAAHAQIAAmPQAAtwYABAAAAABrYXRyYW4gdGVzdCBwa3Q="
    },
    // 6
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1",
     // dst="10.200.1.1")/TCP(sport=31337, dport=80, flags="A")/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGrU7AqAEBCsgBAXppAFAAAAAAAAAAAFAQIAAn5AAAa2F0cmFuIHRlc3QgcGt0",
     .description = "V4 VIP, no TPR, LRU hit",
     .expectedReturnValue = "XDP_TX",
     // "Ether(src='x02', dst='0xdeadbeaf')/IP(src='172.16.104.123',
     // dst='10.0.0.3')/IP(src='192.168.1.1', dst='10.200.1.1')/TCP(flags=16L,
     // dport=80, sport=31337, options=[])/Raw(load='katran test pkt')"
     .expectedOutputPacket = "AADerb6vAgAAAAAACABFAABLAAAAAEAEXCGsEGh7CgAAA0UAADcAAQAAQAatTsCoAQEKyAEBemkAUAAAAAAAAAAAUBAgACfkAABrYXRyYW4gdGVzdCBwa3Q="
    },
    // 7
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1",
     // dst="10.200.1.1")/TCP(sport=31337, dport=80, flags="A", options=[(0xb7,
     // '\x01x04\x00\x00')])/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAACABFAAA/AAEAAEAGrUbAqAEBCsgBAXppAFAAAAAAAAAAAHAQIABP0QAAtwYBBAAAAABrYXRyYW4gdGVzdCBwa3Q=",
     .description = "V4 VIP, TPR Id: 1025, bypasses LRU",
     .expectedReturnValue = "XDP_TX",
     // "Ether(src='x02', dst='0xdeadbeaf')/IP(src='172.16.104.123',
     // dst='10.0.0.3')/IP(src='192.168.1.1', dst='10.200.1.1')/TCP(flags=16L,
     // dport=80, sport=31337, options=[(183, '\\x01\\x04\\x00\\x00'), ('EOL',
     // None)])/Raw(load='katran test pkt')"
     .expectedOutputPacket = "AADerb6vAgAAAAAACABFAABTAAAAAEAEXBmsEGh7CgAAA0UAAD8AAQAAQAatRsCoAQEKyAEBemkAUAAAAAAAAAAAcBAgAE/RAAC3BgEEAAAAAGthdHJhbiB0ZXN0IHBrdA=="
    },
    // 8
    {// Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1",
     // dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A",
     // options=[('Timestamp', (1,3)),('NOP', 0),('NOP', 0)])/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAAC8GQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAgBAgAMQ0AAAICgAAAAEAAAADAQFrYXRyYW4gdGVzdCBwa3Q=",
     .description = "V6 VIP, V6 real, no TPR Id, LRU hit",
     .expectedReturnValue = "XDP_TX",
     // "Ether(src='x02', dst='0xdeadbeaf')/IPv6(src='100::7a69:1',
     // dst='fc00::1')/IPv6(src='fc00:2::1', dst='fc00:1::1')/TCP(flags=16L,
     // dport=80, sport=31337, options=[('Timestamp', (1, 3)), ('NOP', None),
     // ('NOP', None)])/Raw(load='katran test pkt')"
     .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAFcpQAEAAAAAAAAAAAAAAHppAAH8AAAAAAAAAAAAAAAAAAABYAAAAAAvBkD8AAACAAAAAAAAAAAAAAAB/AAAAQAAAAAAAAAAAAAAAXppAFAAAAAAAAAAAIAQIADENAAACAoAAAABAAAAAwEBa2F0cmFuIHRlc3QgcGt0"
    },
    // 9
    {// Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1",
     // dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A", options=[(0xb7,
     // '\x00\x00\x00\x00')])/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAACsGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAcBAgACZBAAC3BgAAAAAAAGthdHJhbiB0ZXN0IHBrdA==",
     .description = "V6 VIP, V6 real, TPR Id 0, LRU hit",
     .expectedReturnValue = "XDP_TX",
     // "Ether(src='x02', dst='0xdeadbeaf')/IPv6(src='100::7a69:1',
     // dst='fc00::1')/IPv6(src='fc00:2::1', dst='fc00:1::1')/TCP(flags=16L,
     // dport=80, sport=31337, options=[(183, '\\x00\\x00\\x00\\x00'), ('EOL',
     // None)])/Raw(load='katran test pkt')"
     .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAFMpQAEAAAAAAAAAAAAAAHppAAH8AAAAAAAAAAAAAAAAAAABYAAAAAArBkD8AAACAAAAAAAAAAAAAAAB/AAAAQAAAAAAAAAAAAAAAXppAFAAAAAAAAAAAHAQIAAmQQAAtwYAAAAAAABrYXRyYW4gdGVzdCBwa3Q="
    },
    // 10
    {// Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1",
     // dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A", options=[(0xb7,
     // '\x04\x00')])/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAACcGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAYBAgADJHAAC3BAQAa2F0cmFuIHRlc3QgcGt0",
     .description = "V6 VIP, V6 real, TPR Id: 1024, bad hdr len, LRU hit",
     .expectedReturnValue = "XDP_TX",
     // "Ether(src='x02', dst='0xdeadbeaf')/IPv6(src='100::7a69:1',
     // dst='fc00::1')/IPv6(src='fc00:2::1', dst='fc00:1::1')/TCP(flags=16L,
     // dport=80, sport=31337,  options=[(183, '\\x04\\x00')])/Raw(load='katran
     // test pkt')"
     .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAE8pQAEAAAAAAAAAAAAAAHppAAH8AAAAAAAAAAAAAAAAAAABYAAAAAAnBkD8AAACAAAAAAAAAAAAAAAB/AAAAQAAAAAAAAAAAAAAAXppAFAAAAAAAAAAAGAQIAAyRwAAtwQEAGthdHJhbiB0ZXN0IHBrdA=="
    },
    // 11
    {// Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1",
     // dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A",
     // options=[(0xB7,'\x00\x04\x00\x00')])/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAACsGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAcBAgACY9AAC3BgAEAAAAAGthdHJhbiB0ZXN0IHBrdA==",
     .description = "V6 VIP, V6 real, TPR Id: 1024, bypasses LRU",
     .expectedReturnValue = "XDP_TX",
     // "Ether(src='x02', dst='0xdeadbeaf')/IPv6(src='100::7a69:1',
     // dst='fc00::1')/IPv6(src='fc00:2::1', dst='fc00:1::1')/TCP(flags=16L,
     // dport=80, sport=31337, options=[(183, '\\x00\\x04\\x00\\x00'), ('EOL',
     // None)])/Raw(load='katran test pkt')"
     .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAFMpQAEAAAAAAAAAAAAAAHppAAH8AAAAAAAAAAAAAAAAAAABYAAAAAArBkD8AAACAAAAAAAAAAAAAAAB/AAAAQAAAAAAAAAAAAAAAXppAFAAAAAAAAAAAHAQIAAmPQAAtwYABAAAAABrYXRyYW4gdGVzdCBwa3Q="
    },
    // 12
    {// Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1",
     // dst="fc00:1::1")/TCP(sport=31332, dport=80,flags="A",
     // options=[(0xB7,'\x00\x00\x00\xFF')])/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAACsGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemQAUAAAAAAAAAAAcBAgACVHAAC3BgAAAP8AAGthdHJhbiB0ZXN0IHBrdA==",
     .description = "V6 VIP, V6 real, random TPR Id, LRU Miss, CH",
     .expectedReturnValue = "XDP_TX",
     // "Ether(src='x02', dst='0xdeadbeaf')/IPv6(src='100::7a64:1',
     // dst='fc00::1')/IPv6(src='fc00:2::1', dst='fc00:1::1')/TCP(flags=16L,
     // dport=80, sport=31337, options=[(183, '\\x00\\x00\\x00\\xff'), ('EOL',
     // None)])/Raw(load='katran test pkt')"
     .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAFMpQAEAAAAAAAAAAAAAAHpkAAH8AAAAAAAAAAAAAAAAAAABYAAAAAArBkD8AAACAAAAAAAAAAAAAAAB/AAAAQAAAAAAAAAAAAAAAXpkAFAAAAAAAAAAAHAQIAAlRwAAtwYAAAD/AABrYXRyYW4gdGVzdCBwa3Q="
    },
    // 13
    {//Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1", dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A", options=[\
    ('NOP', 0),('NOP', 0),('NOP', 0),('NOP', 0),('NOP', 0),('NOP', 0),('NOP', 0),('NOP', 0),('NOP', 0),('NOP', 0),('NOP', 0),('NOP', 0),('NOP', 0),('NOP', 0),\
    (0xB7,'\x00\x04\x00\x00')])/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAADcGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAoBAgAO8pAAABAQEBAQEBAQEBAQEBAbcGAAQAAGthdHJhbiB0ZXN0IHBrdA==",
     .description = "V6 VIP, V6 real, lots of hdr-opts, TPR Id: 1024",
     .expectedReturnValue = "XDP_TX",
     // "Ether(src='x02', dst='0xdeadbeaf')/IPv6(src='100::7a69:1',
     // dst='fc00::1')/IPv6(src='fc00:2::1', dst='fc00:1::1')/TCP(flags=16L,
     // dport=80, sport=31337, options=[('NOP', None), ('NOP', None), ('NOP',
     // None), ('NOP', None), ('NOP', None), ('NOP', None), ('NOP', None),
     // ('NOP', None), ('NOP', None), ('NOP', None), ('NOP', None), ('NOP',
     // None), ('NOP', None), ('NOP', None), (183,
     // '\\x00\\x04\\x00\\x00')])/Raw(load='katran test pkt')"
     .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAF8pQAEAAAAAAAAAAAAAAHppAAH8AAAAAAAAAAAAAAAAAAABYAAAAAA3BkD8AAACAAAAAAAAAAAAAAAB/AAAAQAAAAAAAAAAAAAAAXppAFAAAAAAAAAAAKAQIADvKQAAAQEBAQEBAQEBAQEBAQG3BgAEAABrYXRyYW4gdGVzdCBwa3Q="
    },
    // 14
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1",
     // dst="10.200.1.4")/TCP(sport=31337, dport=42, flags="A")/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGrUvAqAEBCsgBBHppACoAAAAAAAAAAFAQIAAoBwAAa2F0cmFuIHRlc3QgcGt0",
     .description = "packet #1 dst port hashing only",
     .expectedReturnValue = "XDP_TX",
     // "Ether(src='x02', dst='0xdeadbeaf')/IP(src='172.16.104.123',
     // dst='10.0.0.2')/IP(src='192.168.1.1', dst='10.200.1.4')/TCP(flags=16L,
     // dport=42, sport=31337, options=[])/Raw(load='katran test pkt')"
     .expectedOutputPacket = "AADerb6vAgAAAAAACABFAABLAAAAAEAEWyOsEGl6CgAAAkUAADcAAQAAQAatS8CoAQEKyAEEemkAKgAAAAAAAAAAUBAgACgHAABrYXRyYW4gdGVzdCBwa3Q="
    },
    // 15
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.100",
     // dst="10.200.1.4")/TCP(sport=1337, dport=42, flags="A",
     // options=[(0xB7,'\xff\x03\x00\x00')])/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAACABFAAA/AAEAAEAGrODAqAFkCsgBBAU5ACoAAAAAAAAAAHAQIADGwQAAtwb/AwAAAABrYXRyYW4gdGVzdCBwa3Q=",
     .description = "packet #2 dst port hashing only, TPR ID: 1023, bypasses LRU.",
     .expectedReturnValue = "XDP_TX",
     // "Ether(src='x02', dst='0xdeadbeaf')/IP(src='172.16.105.122',
     // dst='10.0.0.2')/IP(src='192.168.1.1', dst='10.200.1.4')/TCP(flags=16L,
     // dport=42, sport=31337, options=[(183, '\\xff\\x03\\x00\\x00'), ('EOL',
     // None)])/Raw(load='katran test pkt')"
     .expectedOutputPacket = "AADerb6vAgAAAAAACABFAABTAAAAAEAEjDSsEDhhCgAAAkUAAD8AAQAAQAas4MCoAWQKyAEEBTkAKgAAAAAAAAAAcBAgAMbBAAC3Bv8DAAAAAGthdHJhbiB0ZXN0IHBrdA=="
    },
    // 16
    {// Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1",
     // dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A", options=[('EOL',
     // None),(0xB7,'\x01\x04\x00\x00')])/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAACsGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAcBAgANKPAAAAtwYBBAAAAGthdHJhbiB0ZXN0IHBrdA==",
     .description = "V6 VIP, V6 real, EOL before TPR, LRU hit",
     .expectedReturnValue = "XDP_TX",
     // "Ether(src='x02', dst='0xdeadbeaf')/IPv6(src='100::7a69:1',
     // dst='fc00::1')/IPv6(src='fc00:2::1', dst='fc00:1::1')/TCP(flags=16L,
     // dport=80, sport=31337, options=[('EOL', None)])/Raw(load='katran test
     // pkt')"
     .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAFMpQAEAAAAAAAAAAAAAAHppAAH8AAAAAAAAAAAAAAAAAAABYAAAAAArBkD8AAACAAAAAAAAAAAAAAAB/AAAAQAAAAAAAAAAAAAAAXppAFAAAAAAAAAAAHAQIADSjwAAALcGAQQAAABrYXRyYW4gdGVzdCBwa3Q="
    },
    // 17
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1",
     // dst="10.200.1.3")/TCP(sport=31337, dport=80, flags="A", options=[('NOP',
     // 0),('NOP', 0),('NOP', 0),('NOP', 0),(0xB7, '\xfd\x03\x00\x00')])/"katran
     // test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAACABFAABDAAEAAEAGrUDAqAEBCsgBA3ppAFAAAAAAAAAAAIAQIABAyQAAAQEBAbcG/QMAAAAAa2F0cmFuIHRlc3QgcGt0",
     .description = "V4 VIP (and v6 real), TPR Id: 1021. Invalid server id. CH",
     .expectedReturnValue = "XDP_TX",
     // "Ether(src='x02', dst='0xdeadbeaf')/IPv6(src='100::bac1:101',
     // dst='fc00::1')/IP(src='192.168.1.1', dst='10.200.1.3')/TCP(flags=16L,
     // dport=80, sport=31337, options=[('NOP', None), ('NOP', None), ('NOP',
     // None), ('NOP', None), (183, '\\xfd\\x03\\x00\\x00'), ('EOL',
     // None)])/Raw(load='katran test pkt')"
     .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAEMEQAEAAAAAAAAAAAAAALrBAQH8AAAAAAAAAAAAAAAAAAACRQAAQwABAABABq1AwKgBAQrIAQN6aQBQAAAAAAAAAACAECAAQMkAAAEBAQG3Bv0DAAAAAGthdHJhbiB0ZXN0IHBrdA=="
    },
};

/**
 * TPR test fixtures with GUE encapsulation expected outputs.
 * These are the same input packets as tprTestFixtures but with 
 * expected outputs using GUE encapsulation instead of IPIP.
 */
const std::vector<PacketAttributes> tprGueTestFixtures = {
    // 1
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1",
     // dst="10.200.1.1")/TCP(sport=31337, dport=80, flags="S", options=[(0xb7,
     // '\x13\x00\x00\x00'),('NOP', 0),('NOP', 0)])/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAACABFAAA/AAEAAEAGrUbAqAEBCsgBAXppAFAAAAAAAAAAAHACIAA84gAAtwYTAAAAAQFrYXRyYW4gdGVzdCBwa3Q=",
     .description = "V4 VIP (and v4 real), SYN, TPR id ignored",
     .expectedReturnValue = "XDP_TX",
     .expectedOutputPacket = "AADerb6vAgAAAAAACABFAABbAAAAAEARWWsKAA0lCgAAA2h7Jp4ARxzDRQAAPwABAABABq1GwKgBAQrIAQF6aQBQAAAAAAAAAABwAiAAPOIAALcGEwAAAAEBa2F0cmFuIHRlc3QgcGt0"
    },
    // 2
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1",
     // dst="10.200.1.1")/TCP(sport=31337, dport=80, flags="A", options=[(0xb7,
     // '\x01\x04\x00\x00'),('NOP', 0),('NOP', 0)])/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAACABFAAA/AAEAAEAGrUbAqAEBCsgBAXppAFAAAAAAAAAAAHAQIABO0AAAtwYBBAAAAQFrYXRyYW4gdGVzdCBwa3Q=",
     .description = "V4 VIP (and v4 real), TPR Id: 1025",
     .expectedReturnValue = "XDP_TX",
     .expectedOutputPacket = "AADerb6vAgAAAAAACABFAABbAAAAAEARWWsKAA0lCgAAA2h7Jp4ARxzDRQAAPwABAABABq1GwKgBAQrIAQF6aQBQAAAAAAAAAABwECAATtAAALcGAQQAAAEBa2F0cmFuIHRlc3QgcGt0"
    },
    // 3
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1",
     // dst="10.200.1.2")/TCP(sport=31337, dport=42, flags="A", options=[(0xb7,
     // '\xff\x03\x00\x00')])/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAACABFAAA/AAEAAEAGrUXAqAEBCsgBAnppACoAAAAAAAAAAHAQIABR9gAAtwb/AwAAAABrYXRyYW4gdGVzdCBwa3Q=",
     .description = "V4 VIP (and v4 real; any dst ports), TPR Id: 1023",
     .expectedReturnValue = "XDP_TX",
     .expectedOutputPacket = "AADerb6vAgAAAAAACABFAABbAAAAAEARWWwKAA0lCgAAAmh7Jp4ARxzFRQAAPwABAABABq1FwKgBAQrIAQJ6aQAqAAAAAAAAAABwECAAUfYAALcG/wMAAAAAa2F0cmFuIHRlc3QgcGt0"
    },
    // 4
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1",
     // dst="10.200.1.3")/TCP(sport=31337, dport=80, flags="A", options=[('NOP',
     // 0),('NOP', 0),('NOP', 0),('NOP', 0),(0xB7, '\x00\x04\x00\x00')])/"katran
     // test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAACABFAABDAAEAAEAGrUDAqAEBCsgBA3ppAFAAAAAAAAAAAIAQIABAyQAAAQEBAbcGAgQAAAAAa2F0cmFuIHRlc3QgcGt0",
     .description = "V4 VIP (and v6 real), TPR Id: 1026.",
     .expectedReturnValue = "XDP_TX",
     .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAEsRQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAACe2gmngBL/LlFAABDAAEAAEAGrUDAqAEBCsgBA3ppAFAAAAAAAAAAAIAQIABAyQAAAQEBAbcGAgQAAAAAa2F0cmFuIHRlc3QgcGt0"
    },
    // 5
    {// Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1",
     // dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A",
     // options=[(0xB7,'\x00\x04\x00\x00')])/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAACsGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAcBAgACY9AAC3BgAEAAAAAGthdHJhbiB0ZXN0IHBrdA==",
     .description = "V6 VIP (and v6 real), TPR Id: 1024",
     .expectedReturnValue = "XDP_TX",
     // GUE encapsulation with IPv6: Ether/IPv6/UDP(dport=9886)/IPv6/TCP
     .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAFsRQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAABemkmngBbybVgAAAAACsGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAcBAgACY9AAC3BgAEAAAAAGthdHJhbiB0ZXN0IHBrdA=="
    },
    // 6
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1",
     // dst="10.200.1.1")/TCP(sport=31337, dport=80, flags="A")/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGrU7AqAEBCsgBAXppAFAAAAAAAAAAAFAQIAAn5AAAa2F0cmFuIHRlc3QgcGt0",
     .description = "V4 VIP, no TPR, LRU hit",
     .expectedReturnValue = "XDP_TX",
     // GUE encapsulation: Ether/IP/UDP(dport=9886)/IP/TCP
     .expectedOutputPacket = "AADerb6vAgAAAAAACABFAABTAAAAAEARWXMKAA0lCgAAA2h7Jp4APxzLRQAANwABAABABq1OwKgBAQrIAQF6aQBQAAAAAAAAAABQECAAJ+QAAGthdHJhbiB0ZXN0IHBrdA=="
    },
    // 7
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1",
     // dst="10.200.1.1")/TCP(sport=31337, dport=80, flags="A", options=[(0xb7,
     // '\x01x04\x00\x00')])/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAACABFAAA/AAEAAEAGrUbAqAEBCsgBAXppAFAAAAAAAAAAAHAQIABP0QAAtwYBBAAAAABrYXRyYW4gdGVzdCBwa3Q=",
     .description = "V4 VIP, TPR Id: 1025, bypasses LRU",
     .expectedReturnValue = "XDP_TX",
     // GUE encapsulation: Ether/IP/UDP(dport=9886)/IP/TCP
     .expectedOutputPacket = "AADerb6vAgAAAAAACABFAABbAAAAAEARWWsKAA0lCgAAA2h7Jp4ARxzDRQAAPwABAABABq1GwKgBAQrIAQF6aQBQAAAAAAAAAABwECAAT9EAALcGAQQAAAAAa2F0cmFuIHRlc3QgcGt0"
    },
    // 8
    {// Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1",
     // dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A",
     // options=[('Timestamp', (1,3)),('NOP', 0),('NOP', 0)])/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAAC8GQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAgBAgAMQ0AAAICgAAAAEAAAADAQFrYXRyYW4gdGVzdCBwa3Q=",
     .description = "V6 VIP, V6 real, no TPR Id, LRU hit",
     .expectedReturnValue = "XDP_TX",
     // GUE encapsulation with IPv6: Ether/IPv6/UDP(dport=9886)/IPv6/TCP
     .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAF8RQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAABemkmngBfya1gAAAAAC8GQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAgBAgAMQ0AAAICgAAAAEAAAADAQFrYXRyYW4gdGVzdCBwa3Q="
    },
    // 9
    {// Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1",
     // dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A", options=[(0xb7,
     // '\x00\x00\x00\x00')])/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAACsGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAcBAgACZBAAC3BgAAAAAAAGthdHJhbiB0ZXN0IHBrdA==",
     .description = "V6 VIP, V6 real, TPR Id 0, LRU hit",
     .expectedReturnValue = "XDP_TX",
     // GUE encapsulation with IPv6: Ether/IPv6/UDP(dport=9886)/IPv6/TCP 
     .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAFsRQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAABemkmngBbybVgAAAAACsGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAcBAgACZBAAC3BgAAAAAAAGthdHJhbiB0ZXN0IHBrdA=="
    },
    // 10
    {// Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1",
     // dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A", options=[(0xb7,
     // '\x04\x00')])/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAACcGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAYBAgADJHAAC3BAQAa2F0cmFuIHRlc3QgcGt0",
     .description = "V6 VIP, V6 real, TPR Id: 1024, bad hdr len, LRU hit",
     .expectedReturnValue = "XDP_TX",
     // GUE encapsulation with IPv6: Ether/IPv6/UDP(dport=9886)/IPv6/TCP
     .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAFcRQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAABemkmngBXyb1gAAAAACcGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAYBAgADJHAAC3BAQAa2F0cmFuIHRlc3QgcGt0"
    },
    // 11
    {// Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1",
     // dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A",
     // options=[(0xB7,'\x00\x04\x00\x00')])/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAACsGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAcBAgACY9AAC3BgAEAAAAAGthdHJhbiB0ZXN0IHBrdA==",
     .description = "V6 VIP, V6 real, TPR Id: 1024, bypasses LRU",
     .expectedReturnValue = "XDP_TX",
     // GUE encapsulation with IPv6: Ether/IPv6/UDP(dport=9886)/IPv6/TCP
     .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAFsRQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAABemkmngBbybVgAAAAACsGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAcBAgACY9AAC3BgAEAAAAAGthdHJhbiB0ZXN0IHBrdA=="
    },
    // 12
    {// Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1",
     // dst="fc00:1::1")/TCP(sport=31332, dport=80,flags="A",
     // options=[(0xB7,'\x00\x00\x00\xFF')])/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAACsGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemQAUAAAAAAAAAAAcBAgACVHAAC3BgAAAP8AAGthdHJhbiB0ZXN0IHBrdA==",
     .description = "V6 VIP, V6 real, random TPR Id, LRU Miss, CH",
     .expectedReturnValue = "XDP_TX",
     // GUE encapsulation with IPv6: Ether/IPv6/UDP(dport=9886)/IPv6/TCP
     .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAFsRQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAABemQmngBbybpgAAAAACsGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemQAUAAAAAAAAAAAcBAgACVHAAC3BgAAAP8AAGthdHJhbiB0ZXN0IHBrdA=="
    },
    // 13
    {//Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1", dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A", options=[\
    ('NOP', 0),('NOP', 0),('NOP', 0),('NOP', 0),('NOP', 0),('NOP', 0),('NOP', 0),('NOP', 0),('NOP', 0),('NOP', 0),('NOP', 0),('NOP', 0),('NOP', 0),('NOP', 0),\
    (0xB7,'\x00\x04\x00\x00')])/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAADcGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAoBAgAO8pAAABAQEBAQEBAQEBAQEBAbcGAAQAAGthdHJhbiB0ZXN0IHBrdA==",
     .description = "V6 VIP, V6 real, lots of hdr-opts, TPR Id: 1024",
     .expectedReturnValue = "XDP_TX",
     // GUE encapsulation with IPv6: Ether/IPv6/UDP(dport=9886)/IPv6/TCP
     .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAGcRQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAABemkmngBnyZ1gAAAAADcGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAoBAgAO8pAAABAQEBAQEBAQEBAQEBAbcGAAQAAGthdHJhbiB0ZXN0IHBrdA=="
    },
    // 14
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1",
     // dst="10.200.1.4")/TCP(sport=31337, dport=42, flags="A")/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGrUvAqAEBCsgBBHppACoAAAAAAAAAAFAQIAAoBwAAa2F0cmFuIHRlc3QgcGt0",
     .description = "packet #1 dst port hashing only",
     .expectedReturnValue = "XDP_TX",
     // GUE encapsulation: Ether/IP/UDP(dport=9886)/IP/TCP
     .expectedOutputPacket = "AADerb6vAgAAAAAACABFAABTAAAAAEARWXQKAA0lCgAAAml6Jp4APxvQRQAANwABAABABq1LwKgBAQrIAQR6aQAqAAAAAAAAAABQECAAKAcAAGthdHJhbiB0ZXN0IHBrdA=="
    },
    // 15
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.100",
     // dst="10.200.1.4")/TCP(sport=1337, dport=42, flags="A",
     // options=[(0xB7,'\xff\x03\x00\x00')])/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAACABFAAA/AAEAAEAGrODAqAFkCsgBBAU5ACoAAAAAAAAAAHAQIADGwQAAtwb/AwAAAABrYXRyYW4gdGVzdCBwa3Q=",
     .description = "packet #2 dst port hashing only, TPR ID: 1023, bypasses LRU.",
     .expectedReturnValue = "XDP_TX",
     // GUE encapsulation: Ether/IP/UDP(dport=9886)/IP/TCP
     .expectedOutputPacket = "AADerb6vAgAAAAAACABFAABbAAAAAEARWWwKAA0lCgAAAjhhJp4AR01ERQAAPwABAABABqzgwKgBZArIAQQFOQAqAAAAAAAAAABwECAAxsEAALcG/wMAAAAAa2F0cmFuIHRlc3QgcGt0"
    },
    // 16
    {// Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1",
     // dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A", options=[('EOL',
     // None),(0xB7,'\x01\x04\x00\x00')])/"katran test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAACsGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAcBAgANKPAAAAtwYBBAAAAGthdHJhbiB0ZXN0IHBrdA==",
     .description = "V6 VIP, V6 real, EOL before TPR, LRU hit",
     .expectedReturnValue = "XDP_TX",
     // GUE encapsulation with IPv6: Ether/IPv6/UDP(dport=9886)/IPv6/TCP
     .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAFsRQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAABemkmngBbybVgAAAAACsGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAcBAgANKPAAAAtwYBBAAAAGthdHJhbiB0ZXN0IHBrdA=="
    },
    // 17
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1",
     // dst="10.200.1.3")/TCP(sport=31337, dport=80, flags="A", options=[('NOP',
     // 0),('NOP', 0),('NOP', 0),('NOP', 0),(0xB7, '\xfd\x03\x00\x00')])/"katran
     // test pkt"
     .inputPacket = "AgAAAAAAAQAAAAAACABFAABDAAEAAEAGrUDAqAEBCsgBA3ppAFAAAAAAAAAAAIAQIABAyQAAAQEBAbcG/QMAAAAAa2F0cmFuIHRlc3QgcGt0",
     .description = "V4 VIP (and v6 real), TPR Id: 1021. Invalid server id. CH",
     .expectedReturnValue = "XDP_TX",
     // GUE encapsulation with IPv6 outer: Ether/IPv6/UDP(dport=9886)/IP/TCP
     .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAEsRQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAACe2gmngBL/LlFAABDAAEAAEAGrUDAqAEBCsgBA3ppAFAAAAAAAAAAAIAQIABAyQAAAQEBAbcG/QMAAAAAa2F0cmFuIHRlc3QgcGt0"
    }
};

} // namespace testing
} // namespace katran
