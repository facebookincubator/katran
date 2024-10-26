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
 */
const std::vector<::katran::PacketAttributes> udpStableRtFixtures = {
    // 1
    {// Ether(src="0x1", dst="0x2")/IPv6(src="fc00:1::1",
    // dst="fc00:1::9")/UDP(sport=31337, dport=80)/Raw(load=b'\x80\x00\x00\x00\x00\x00\x00\x00local test pkt')
     .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAAB4RQPwAAAEAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAAJemkAUAAeXTuAAAAAAAAAAGxvY2FsIHRlc3QgcGt0",
     .description = "Stable Rt packet with conn-id 0",
     .expectedReturnValue = "XDP_TX",
     .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAE4RQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAADemkmngBOvthgAAAAAB4RQPwAAAEAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAAJemkAUAAeXTuAAAAAAAAAAGxvY2FsIHRlc3QgcGt0"
    },
    // 2
    {// Ether(src="0x1", dst="0x2")/IPv6(src="fc00:1::1",
     // dst="fc00:1::9")/UDP(sport=31337, dport=80)/Raw(load=b'\x80\x03\x04\x03\x00\x00\x00\x00local test pkt')
    .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAAB4RQPwAAAEAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAAJemkAUAAeWTWAAwQDAAAAAGxvY2FsIHRlc3QgcGt0",
    .description = "Stable Rt packet from same src, with conn-id for fc00::3 real",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAE4RQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAADemkmngBOvthgAAAAAB4RQPwAAAEAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAAJemkAUAAeWTWAAwQDAAAAAGxvY2FsIHRlc3QgcGt0"
    },
    // 3
    {// Ether(src="0x1", dst="0x2")/IPv6(src="fc00:1::1",
    // dst="fc00:1::9")/UDP(sport=31339, dport=80)/Raw(load=b'\x80\x03\x04\x03\x00\x00\x00\x00local test pkt')
    .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAAB4RQPwAAAEAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAAJemsAUAAeWTOAAwQDAAAAAGxvY2FsIHRlc3QgcGt0",
    .description = "Stable Rt packet from different src port, with conn-id for fc00::3 real",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAE4RQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAADemsmngBOvtZgAAAAAB4RQPwAAAEAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAAJemsAUAAeWTOAAwQDAAAAAGxvY2FsIHRlc3QgcGt0"
    },
    // 4
    {// Ether(src="0x1", dst="0x2")/IPv6(src="fc00:1::5",
    // dst="fc00:1::9")/UDP(sport=31339, dport=80)/Raw(load=b'\x80\x03\x04\x03\x00\x00\x00\x00local test pkt')
    .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAAB4RQPwAAAEAAAAAAAAAAAAAAAX8AAABAAAAAAAAAAAAAAAJemsAUAAeWS+AAwQDAAAAAGxvY2FsIHRlc3QgcGt0",
    .description = "Stable Rt packet from different src ip, with same conn-id for fc00::3 real",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAE4RQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAADemsmngBOvtZgAAAAAB4RQPwAAAEAAAAAAAAAAAAAAAX8AAABAAAAAAAAAAAAAAAJemsAUAAeWS+AAwQDAAAAAGxvY2FsIHRlc3QgcGt0"
    },
    // 5
    {// Ether(src="0x1", dst="0x2")/IPv6(src="fc00:1::1",
    // dst="fc00:1::9")/UDP(sport=31337, dport=80)/Raw(load=b'\x80\x00\x00\x00\x00\x00\x00\x00local test pkt')
    .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAAB4RQPwAAAEAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAAJemkAUAAeXTuAAAAAAAAAAGxvY2FsIHRlc3QgcGt0",
    .description = "Stable Rt packet with conn-id 0, from same original src ip/port, so LRU hit",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAE4RQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAADemkmngBOvthgAAAAAB4RQPwAAAEAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAAJemkAUAAeXTuAAAAAAAAAAGxvY2FsIHRlc3QgcGt0"
    }
};
}
}
