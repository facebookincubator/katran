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
 * 1) create packets (obtain base64 encoding as: str(pkt).encode("base64"))
 * 2) pckts = [ <created packets from above> ]
 * 3) wrpcap(<path_to_file>, pckts)
 */
const std::vector<std::pair<std::string, std::string>> inputTPRTestFixtures = {
  //1
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.1")/TCP(sport=31337, dport=80, flags="S", options=[(0xb7, '\x13\x00\x00\x00'),('NOP', 0),('NOP', 0)])/"katran test pkt"
    "AgAAAAAAAQAAAAAACABFAAA/AAEAAEAGrUbAqAEBCsgBAXppAFAAAAAAAAAAAHACIAA84gAAtwYTAAAAAQFrYXRyYW4gdGVzdCBwa3Q=",
    "V4 VIP (and v4 real), SYN, TPR id ignored"
  },
  //2
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.1")/TCP(sport=31337, dport=80, flags="A", options=[(0xb7, '\x01\x04\x00\x00'),('NOP', 0),('NOP', 0)])/"katran test pkt"
    "AgAAAAAAAQAAAAAACABFAAA/AAEAAEAGrUbAqAEBCsgBAXppAFAAAAAAAAAAAHAQIABO0AAAtwYBBAAAAQFrYXRyYW4gdGVzdCBwa3Q=",
    "V4 VIP (and v4 real), TPR Id: 1025"
  },
  //3
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.2")/TCP(sport=31337, dport=42, flags="A", options=[(0xb7, '\xff\x03\x00\x00')])/"katran test pkt"
    "AgAAAAAAAQAAAAAACABFAAA/AAEAAEAGrUXAqAEBCsgBAnppACoAAAAAAAAAAHAQIABR9gAAtwb/AwAAAABrYXRyYW4gdGVzdCBwa3Q=",
    "V4 VIP (and v4 real; any dst ports), TPR Id: 1023"
  },
  //4
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.3")/TCP(sport=31337, dport=80, flags="A", options=[('NOP', 0),('NOP', 0),('NOP', 0),('NOP', 0),(0xB7, '\xfe\x03\x00\x00')])/"katran test pkt"
    "AgAAAAAAAQAAAAAACABFAABDAAEAAEAGrUDAqAEBCsgBA3ppAFAAAAAAAAAAAIAQIABAyQAAAQEBAbcG/gMAAAAAa2F0cmFuIHRlc3QgcGt0",
    "V4 VIP (and v6 real), TPR Id: 1022. Real at 0. CH."
  },
  //5
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1", dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A", options=[(0xB7,'\x00\x04\x00\x00')])/"katran test pkt"
    "AgAAAAAAAQAAAAAAht1gAAAAACsGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAcBAgACY9AAC3BgAEAAAAAGthdHJhbiB0ZXN0IHBrdA==",
    "V6 VIP (and v6 real), TPR Id: 1024"
  },
  //6
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.1")/TCP(sport=31337, dport=80, flags="A")/"katran test pkt"
    "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGrU7AqAEBCsgBAXppAFAAAAAAAAAAAFAQIAAn5AAAa2F0cmFuIHRlc3QgcGt0",
    "V4 VIP, no TPR, LRU hit"
  },
  //7
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.1")/TCP(sport=31337, dport=80, flags="A", options=[(0xb7, '\x01x04\x00\x00')])/"katran test pkt"
    "AgAAAAAAAQAAAAAACABFAAA/AAEAAEAGrUbAqAEBCsgBAXppAFAAAAAAAAAAAHAQIABP0QAAtwYBBAAAAABrYXRyYW4gdGVzdCBwa3Q=",
    "V4 VIP, TPR Id: 1025, bypasses LRU"
  },
  //8
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1", dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A", options=[('Timestamp', (1,3)),('NOP', 0),('NOP', 0)])/"katran test pkt"
    "AgAAAAAAAQAAAAAAht1gAAAAAC8GQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAgBAgAMQ0AAAICgAAAAEAAAADAQFrYXRyYW4gdGVzdCBwa3Q=",
    "V6 VIP, V6 real, no TPR Id, LRU hit"
  },
  //9
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1", dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A", options=[(0xb7, '\x00\x00\x00\x00')])/"katran test pkt"
    "AgAAAAAAAQAAAAAAht1gAAAAACsGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAcBAgACZBAAC3BgAAAAAAAGthdHJhbiB0ZXN0IHBrdA==",
    "V6 VIP, V6 real, TPR Id 0, LRU hit"
  },
  //10
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1", dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A", options=[(0xb7, '\x04\x00')])/"katran test pkt"
    "AgAAAAAAAQAAAAAAht1gAAAAACcGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAYBAgADJHAAC3BAQAa2F0cmFuIHRlc3QgcGt0",
    "V6 VIP, V6 real, TPR Id: 1024, bad hdr len, LRU hit"
  },
  //11
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1", dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A", options=[(0xB7,'\x00\x04\x00\x00')])/"katran test pkt"
    "AgAAAAAAAQAAAAAAht1gAAAAACsGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAcBAgACY9AAC3BgAEAAAAAGthdHJhbiB0ZXN0IHBrdA==",
    "V6 VIP, V6 real, TPR Id: 1024, bypasses LRU"
  },
  //12
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1", dst="fc00:1::1")/TCP(sport=31332, dport=80,flags="A", options=[(0xB7,'\x00\x00\x00\xFF')])/"katran test pkt"
    "AgAAAAAAAQAAAAAAht1gAAAAACsGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemQAUAAAAAAAAAAAcBAgACVHAAC3BgAAAP8AAGthdHJhbiB0ZXN0IHBrdA==",
    "V6 VIP, V6 real, random TPR Id, LRU Miss, CH"
  },
  //13
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1", dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A", options=[\
    ('NOP', 0),('NOP', 0),('NOP', 0),('NOP', 0),('NOP', 0),('NOP', 0),('NOP', 0),('NOP', 0),('NOP', 0),('NOP', 0),('NOP', 0),('NOP', 0),('NOP', 0),('NOP', 0),\
    (0xB7,'\x00\x04\x00\x00')])/"katran test pkt"
    "AgAAAAAAAQAAAAAAht1gAAAAADcGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAoBAgAO8pAAABAQEBAQEBAQEBAQEBAbcGAAQAAGthdHJhbiB0ZXN0IHBrdA==",
    "V6 VIP, V6 real, lots of hdr-opts, TPR Id: 1024"
  },
  //14
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.4")/TCP(sport=31337, dport=42, flags="A")/"katran test pkt"
    "AgAAAAAAAQAAAAAACABFAAA3AAEAAEAGrUvAqAEBCsgBBHppACoAAAAAAAAAAFAQIAAoBwAAa2F0cmFuIHRlc3QgcGt0",
    "packet #1 dst port hashing only"
  },
  //15
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.100", dst="10.200.1.4")/TCP(sport=1337, dport=42, flags="A",  options=[(0xB7,'\xff\x03\x00\x00')])/"katran test pkt"
    "AgAAAAAAAQAAAAAACABFAAA/AAEAAEAGrODAqAFkCsgBBAU5ACoAAAAAAAAAAHAQIADGwQAAtwb/AwAAAABrYXRyYW4gdGVzdCBwa3Q=",
    "packet #2 dst port hashing only, TPR ID: 1023, bypasses LRU."
  },
  //16
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1", dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A", options=[('EOL', None),(0xB7,'\x01\x04\x00\x00')])/"katran test pkt"
    "AgAAAAAAAQAAAAAAht1gAAAAACsGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAcBAgANKPAAAAtwYBBAAAAGthdHJhbiB0ZXN0IHBrdA==",
    "V6 VIP, V6 real, EOL before TPR, LRU hit"
  },
};

const std::vector<std::pair<std::string, std::string>> outputTPRTestFixtures = {
  // Note: comment on each output represents the expected packet attributes.
  // Generated in scapy as: Ether(base64.b64decode(outputTPRTestFixtures[i].encode('ascii'))).command()
  //1
  {
    // "Ether(src='x02', dst='0xdeadbeaf')/IP(src='172.16.104.123', dst='10.0.0.3'/IP(src='192.168.1.1', dst='10.200.1.1'/TCP(dport=80, sport=31337, flags=2L, options=[(183, '\\x13\\x00\\x00\\x00'), ('NOP', None), ('NOP', None)])/Raw(load='katran test pkt')"
    "AADerb6vAgAAAAAACABFAABTAAAAAEAEXBmsEGh7CgAAA0UAAD8AAQAAQAatRsCoAQEKyAEBemkAUAAAAAAAAAAAcAIgADziAAC3BhMAAAABAWthdHJhbiB0ZXN0IHBrdA==",
    "XDP_TX"
  },
  //2
  {
    // "Ether(src='x02', dst='0xdeadbeaf')/IP(src='172.16.104.123', dst='10.0.0.3'/IP(src='192.168.1.1', dst='10.200.1.1'/TCP(dport=80, sport=31337, flags=16L, options=[(183, '\\x01\\x04\\x00\\x00'), ('NOP', None), ('NOP', None)])/Raw(load='katran test pkt')"
    "AADerb6vAgAAAAAACABFAABTAAAAAEAEXBmsEGh7CgAAA0UAAD8AAQAAQAatRsCoAQEKyAEBemkAUAAAAAAAAAAAcBAgAE7QAAC3BgEEAAABAWthdHJhbiB0ZXN0IHBrdA==",
    "XDP_TX"
  },
  //3
  {
    // "Ether(src='x02', dst='0xdeadbeaf')/IP(src='172.16.104.123', dst='10.0.0.2')/IP(src='192.168.1.1', dst='10.200.1.2')/TCP(flags=16L, dport=42, sport=31337, options=[(183, '\\xff\\x03\\x00\\x00'), ('EOL', None)])/Raw(load='katran test pkt')"
    "AADerb6vAgAAAAAACABFAABTAAAAAEAEXBqsEGh7CgAAAkUAAD8AAQAAQAatRcCoAQEKyAECemkAKgAAAAAAAAAAcBAgAFH2AAC3Bv8DAAAAAGthdHJhbiB0ZXN0IHBrdA==",
    "XDP_TX"
  },
  //4
  {
    // "Ether(src='x02', dst='0xdeadbeaf')/IPv6(src='100::bac1:101', dst='fc00::1')/IP(src='192.168.1.1', dst='10.200.1.3')/TCP(flags=16L, dport=80, sport=31337, options=[('NOP', None), ('NOP', None), ('NOP', None), ('NOP', None), (183, '\\xfe\\x03\\x00\\x00'), ('EOL', None)])/Raw(load='katran test pkt')"
    "AADerb6vAgAAAAAAht1gAAAAAEMEQAEAAAAAAAAAAAAAALrBAQH8AAAAAAAAAAAAAAAAAAABRQAAQwABAABABq1AwKgBAQrIAQN6aQBQAAAAAAAAAACAECAAQMkAAAEBAQG3Bv4DAAAAAGthdHJhbiB0ZXN0IHBrdA==",
    "XDP_TX"
  },
  //5
  {
    // "Ether(src='x02', dst='0xdeadbeaf')/IPv6(src='100::7a69:1', dst='fc00::1')/IPv6(src='fc00:2::1', dst='fc00:1::1')/TCP(flags=16L, dport=80, sport=31337, options=[(183, '\\x00\\x04\\x00\\x00'), ('EOL', None)])/Raw(load='katran test pkt')"
    "AADerb6vAgAAAAAAht1gAAAAAFMpQAEAAAAAAAAAAAAAAHppAAH8AAAAAAAAAAAAAAAAAAABYAAAAAArBkD8AAACAAAAAAAAAAAAAAAB/AAAAQAAAAAAAAAAAAAAAXppAFAAAAAAAAAAAHAQIAAmPQAAtwYABAAAAABrYXRyYW4gdGVzdCBwa3Q=",
    "XDP_TX"
  },
  //6
  {
    // "Ether(src='x02', dst='0xdeadbeaf')/IP(src='172.16.104.123', dst='10.0.0.3')/IP(src='192.168.1.1', dst='10.200.1.1')/TCP(flags=16L, dport=80, sport=31337, options=[])/Raw(load='katran test pkt')"
    "AADerb6vAgAAAAAACABFAABLAAAAAEAEXCGsEGh7CgAAA0UAADcAAQAAQAatTsCoAQEKyAEBemkAUAAAAAAAAAAAUBAgACfkAABrYXRyYW4gdGVzdCBwa3Q=",
    "XDP_TX"
  },
  //7
  {
    // "Ether(src='x02', dst='0xdeadbeaf')/IP(src='172.16.104.123', dst='10.0.0.3')/IP(src='192.168.1.1', dst='10.200.1.1')/TCP(flags=16L, dport=80, sport=31337, options=[(183, '\\x01\\x04\\x00\\x00'), ('EOL', None)])/Raw(load='katran test pkt')"
    "AADerb6vAgAAAAAACABFAABTAAAAAEAEXBmsEGh7CgAAA0UAAD8AAQAAQAatRsCoAQEKyAEBemkAUAAAAAAAAAAAcBAgAE/RAAC3BgEEAAAAAGthdHJhbiB0ZXN0IHBrdA==",
    "XDP_TX"
  },
  //8
  {
    // "Ether(src='x02', dst='0xdeadbeaf')/IPv6(src='100::7a69:1', dst='fc00::1')/IPv6(src='fc00:2::1', dst='fc00:1::1')/TCP(flags=16L, dport=80, sport=31337, options=[('Timestamp', (1, 3)), ('NOP', None), ('NOP', None)])/Raw(load='katran test pkt')"
    "AADerb6vAgAAAAAAht1gAAAAAFcpQAEAAAAAAAAAAAAAAHppAAH8AAAAAAAAAAAAAAAAAAABYAAAAAAvBkD8AAACAAAAAAAAAAAAAAAB/AAAAQAAAAAAAAAAAAAAAXppAFAAAAAAAAAAAIAQIADENAAACAoAAAABAAAAAwEBa2F0cmFuIHRlc3QgcGt0",
    "XDP_TX"
  },
  //9
  {
    // "Ether(src='x02', dst='0xdeadbeaf')/IPv6(src='100::7a69:1', dst='fc00::1')/IPv6(src='fc00:2::1', dst='fc00:1::1')/TCP(flags=16L, dport=80, sport=31337, options=[(183, '\\x00\\x00\\x00\\x00'), ('EOL', None)])/Raw(load='katran test pkt')"
    "AADerb6vAgAAAAAAht1gAAAAAFMpQAEAAAAAAAAAAAAAAHppAAH8AAAAAAAAAAAAAAAAAAABYAAAAAArBkD8AAACAAAAAAAAAAAAAAAB/AAAAQAAAAAAAAAAAAAAAXppAFAAAAAAAAAAAHAQIAAmQQAAtwYAAAAAAABrYXRyYW4gdGVzdCBwa3Q=",
    "XDP_TX"
  },
  //10
  {
    // "Ether(src='x02', dst='0xdeadbeaf')/IPv6(src='100::7a69:1', dst='fc00::1')/IPv6(src='fc00:2::1', dst='fc00:1::1')/TCP(flags=16L, dport=80, sport=31337,  options=[(183, '\\x04\\x00')])/Raw(load='katran test pkt')"
    "AADerb6vAgAAAAAAht1gAAAAAE8pQAEAAAAAAAAAAAAAAHppAAH8AAAAAAAAAAAAAAAAAAABYAAAAAAnBkD8AAACAAAAAAAAAAAAAAAB/AAAAQAAAAAAAAAAAAAAAXppAFAAAAAAAAAAAGAQIAAyRwAAtwQEAGthdHJhbiB0ZXN0IHBrdA==",
    "XDP_TX"
  },
  //11
  {
    // "Ether(src='x02', dst='0xdeadbeaf')/IPv6(src='100::7a69:1', dst='fc00::1')/IPv6(src='fc00:2::1', dst='fc00:1::1')/TCP(flags=16L, dport=80, sport=31337, options=[(183, '\\x00\\x04\\x00\\x00'), ('EOL', None)])/Raw(load='katran test pkt')"
    "AADerb6vAgAAAAAAht1gAAAAAFMpQAEAAAAAAAAAAAAAAHppAAH8AAAAAAAAAAAAAAAAAAABYAAAAAArBkD8AAACAAAAAAAAAAAAAAAB/AAAAQAAAAAAAAAAAAAAAXppAFAAAAAAAAAAAHAQIAAmPQAAtwYABAAAAABrYXRyYW4gdGVzdCBwa3Q=",
    "XDP_TX"
  },
  //12
  {
    // "Ether(src='x02', dst='0xdeadbeaf')/IPv6(src='100::7a64:1', dst='fc00::1')/IPv6(src='fc00:2::1', dst='fc00:1::1')/TCP(flags=16L, dport=80, sport=31337, options=[(183, '\\x00\\x00\\x00\\xff'), ('EOL', None)])/Raw(load='katran test pkt')"
    "AADerb6vAgAAAAAAht1gAAAAAFMpQAEAAAAAAAAAAAAAAHpkAAH8AAAAAAAAAAAAAAAAAAABYAAAAAArBkD8AAACAAAAAAAAAAAAAAAB/AAAAQAAAAAAAAAAAAAAAXpkAFAAAAAAAAAAAHAQIAAlRwAAtwYAAAD/AABrYXRyYW4gdGVzdCBwa3Q=",
    "XDP_TX"
  },
  //13
  {
    // "Ether(src='x02', dst='0xdeadbeaf')/IPv6(src='100::7a69:1', dst='fc00::1')/IPv6(src='fc00:2::1', dst='fc00:1::1')/TCP(flags=16L, dport=80, sport=31337, options=[('NOP', None), ('NOP', None), ('NOP', None), ('NOP', None), ('NOP', None), ('NOP', None), ('NOP', None), ('NOP', None), ('NOP', None), ('NOP', None), ('NOP', None), ('NOP', None), ('NOP', None), ('NOP', None), (183, '\\x00\\x04\\x00\\x00')])/Raw(load='katran test pkt')"
    "AADerb6vAgAAAAAAht1gAAAAAF8pQAEAAAAAAAAAAAAAAHppAAH8AAAAAAAAAAAAAAAAAAABYAAAAAA3BkD8AAACAAAAAAAAAAAAAAAB/AAAAQAAAAAAAAAAAAAAAXppAFAAAAAAAAAAAKAQIADvKQAAAQEBAQEBAQEBAQEBAQG3BgAEAABrYXRyYW4gdGVzdCBwa3Q=",
    "XDP_TX"
  },
  //14
  {
    // "Ether(src='x02', dst='0xdeadbeaf')/IP(src='172.16.104.123', dst='10.0.0.2')/IP(src='192.168.1.1', dst='10.200.1.4')/TCP(flags=16L, dport=42, sport=31337, options=[])/Raw(load='katran test pkt')"
    "AADerb6vAgAAAAAACABFAABLAAAAAEAEmp2sECoACgAAAkUAADcAAQAAQAatS8CoAQEKyAEEemkAKgAAAAAAAAAAUBAgACgHAABrYXRyYW4gdGVzdCBwa3Q=",
    "XDP_TX"
  },
  //15
  {
    // "Ether(src='x02', dst='0xdeadbeaf')/IP(src='172.16.104.123', dst='10.0.0.2')/IP(src='192.168.1.1', dst='10.200.1.4')/TCP(flags=16L, dport=42, sport=31337, options=[(183, '\\xff\\x03\\x00\\x00'), ('EOL', None)])/Raw(load='katran test pkt')"
    "AADerb6vAgAAAAAACABFAABTAAAAAEAEjDSsEDhhCgAAAkUAAD8AAQAAQAas4MCoAWQKyAEEBTkAKgAAAAAAAAAAcBAgAMbBAAC3Bv8DAAAAAGthdHJhbiB0ZXN0IHBrdA==",
    "XDP_TX"
  },
  //16
  {
    // "Ether(src='x02', dst='0xdeadbeaf')/IPv6(src='100::7a69:1', dst='fc00::1')/IPv6(src='fc00:2::1', dst='fc00:1::1')/TCP(flags=16L, dport=80, sport=31337, options=[('EOL', None)])/Raw(load='katran test pkt')"
    "AADerb6vAgAAAAAAht1gAAAAAFMpQAEAAAAAAAAAAAAAAHppAAH8AAAAAAAAAAAAAAAAAAABYAAAAAArBkD8AAACAAAAAAAAAAAAAAAB/AAAAQAAAAAAAAAAAAAAAXppAFAAAAAAAAAAAHAQIADSjwAAALcGAQQAAABrYXRyYW4gdGVzdCBwa3Q=",
    "XDP_TX"
  },
};

} // namespace testing
} // namespace katran
