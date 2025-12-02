// clang-format off

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
#include <vector>
#include "katran/lib/testing/tools/PacketAttributes.h"
#include "katran/lib/testing/tools/PacketBuilder.h"

namespace katran {
namespace testing {
/**
 * Input packets generated with PacketBuilder API.
 *
 * Format: PacketAttributes with inputPacketBuilder and
 * expectedOutputPacketBuilder
 *
 * To get base64 packet string from PacketBuilder: builder.build().base64Packet
 */

inline const std::vector<struct __sk_buff> getInputCtxsForHcTest() {
  std::vector<struct __sk_buff> v;
  for (int i = 0; i < 4; i++) {
    struct __sk_buff skb = {};
    skb.mark = i;
    v.push_back(skb);
  }
  return v;
};

inline const std::vector<PacketAttributes> hcTestFixtures = {
    // 1
    {.description = "v4 packet. no fwmark",
     .expectedReturnValue = "TC_ACT_UNSPEC",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv4("192.168.1.1", "10.200.1.1")
         .UDP(31337, 80)
         .payload("katran test pkt"),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv4("192.168.1.1", "10.200.1.1")
         .UDP(31337, 80)
         .payload("katran test pkt")
    },
    // 2
    {.description = "v4 packet. fwmark 1",
     .expectedReturnValue = "TC_ACT_REDIRECT",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv4("192.168.1.1", "10.200.1.1")
         .UDP(31337, 80)
         .payload("katran test pkt"),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("00:ff:de:ad:be:af", "00:00:de:ad:be:af")
         .IPv4("10.0.13.37", "10.0.0.1", 64, 0, 0)
         .IPv4("192.168.1.1", "10.200.1.1")
         .UDP(31337, 80)
         .payload("katran test pkt")
    },
    // 3
    {.description = "v4 packet. fwmark 2",
     .expectedReturnValue = "TC_ACT_REDIRECT",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv4("192.168.1.1", "10.200.1.1")
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt"),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("00:ff:de:ad:be:af", "00:00:de:ad:be:af")
         .IPv4("10.0.13.37", "10.0.0.2", 64, 0, 0)
         .IPv4("192.168.1.1", "10.200.1.1")
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt")
    },
    // 4
    {.description = "v6 packet. fwmark 3",
     .expectedReturnValue = "TC_ACT_REDIRECT",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv6("fc00:2::1", "fc00:1::1")
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt"),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("00:ff:de:ad:be:af", "00:00:de:ad:be:af")
         .IPv6("fc00:2307::1337", "fc00::1")
         .IPv6("fc00:2::1", "fc00:1::1")
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt")
    },
};

// Test fixtures for GUE encapsulation
// Using UDPZeroChecksum for the outer GUE UDP header because BPF sets checksum to 0
inline const std::vector<PacketAttributes> hcGueTestFixtures = {
    // 1
    {.description = "v4 packet. no fwmark",
     .expectedReturnValue = "TC_ACT_UNSPEC",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv4("192.168.1.1", "10.200.1.1")
         .UDP(31337, 80)
         .payload("katran test pkt"),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv4("192.168.1.1", "10.200.1.1")
         .UDP(31337, 80)
         .payload("katran test pkt")
    },
    // 2
    {.description = "v4 packet. fwmark 1",
     .expectedReturnValue = "TC_ACT_REDIRECT",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv4("192.168.1.1", "10.200.1.1")
         .UDP(31337, 80)
         .payload("katran test pkt"),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("00:ff:de:ad:be:af", "00:00:de:ad:be:af")
         .IPv4("10.0.13.37", "10.0.0.1", 64, 0, 0)
         .UDPZeroChecksum(63265, 9886)
         .IPv4("192.168.1.1", "10.200.1.1")
         .UDP(31337, 80)
         .payload("katran test pkt")
    },
    // 3
    {.description = "v4 packet. fwmark 2",
     .expectedReturnValue = "TC_ACT_REDIRECT",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv4("192.168.1.1", "10.200.1.1")
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt"),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("00:ff:de:ad:be:af", "00:00:de:ad:be:af")
         .IPv4("10.0.13.37", "10.0.0.2", 64, 0, 0)
         .UDPZeroChecksum(63265, 9886)
         .IPv4("192.168.1.1", "10.200.1.1")
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt")
    },
    // 4
    {.description = "v6 packet. fwmark 3",
     .expectedReturnValue = "TC_ACT_REDIRECT",
     .inputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("0x1", "0x2")
         .IPv6("fc00:2::1", "fc00:1::1")
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt"),
     .expectedOutputPacketBuilder = katran::testing::PacketBuilder::newPacket()
         .Eth("00:ff:de:ad:be:af", "00:00:de:ad:be:af")
         .IPv6("fc00:2307::1337", "fc00::1")
         .UDPZeroChecksum(63265, 9886)
         .IPv6("fc00:2::1", "fc00:1::1")
         .TCP(31337, 80, 0, 0, 8192, TH_ACK)
         .payload("katran test pkt")
    },
};

} // namespace testing
} // namespace katran
