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
#include "katran/lib/testing/tools/PacketAttributes.h"

namespace katran {
namespace testing {
/**
 * Test fixtures for LPM_SRC_LOOKUP feature
 */
using TestFixture = std::vector<PacketAttributes>;
const TestFixture lpmSrcLookupTestFixtures = {
    // 1
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1",
     // dst="10.200.1.1")/UDP(sport=31337, dport=80)/"katran test pkt"
     .inputPacket =
         "AgAAAAAAAQAAAAAACABFAAArAAEAAEARrU/AqAEBCsgBAXppAFAAF5fea2F0cmFuIHRlc3QgcGt0",
     .description = "ipv4: lpm cached flow. LPM_SRC_LOOKUP is required",
     .expectedReturnValue = "XDP_TX",
     .expectedOutputPacket =
         "AADerb6vAgAAAAAACABFAABHAAAAAEARWX8KAA0lCgAAA2h7F8AAMwAARQAAKwABAABAEa1PwKgBAQrIAQF6aQBQABeX3mthdHJhbiB0ZXN0IHBrdA=="},
    // 2
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.1.2",
     // dst="10.200.1.1")/UDP(sport=31337, dport=80)/"katran test pkt"
     .inputPacket =
         "AgAAAAAAAQAAAAAACABFAAArAAEAAEARrU7AqAECCsgBAXppAFAAF5fda2F0cmFuIHRlc3QgcGt0",
     .description = "ipv4: lpm src lookup /17. LPM_SRC_LOOKUP is required",
     .expectedReturnValue = "XDP_TX",
     .expectedOutputPacket =
         "AADerb6vAgAAAAAAht1gAAAAADMRQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAjBwABe2sXwAAzAABFAAArAAEAAEARrU7AqAECCsgBAXppAFAAF5fda2F0cmFuIHRlc3QgcGt0"},
    // 3
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.100.1",
     // dst="10.200.1.1")/UDP(sport=31337, dport=80)/"katran test pkt"
     .inputPacket =
         "AgAAAAAAAQAAAAAACABFAAArAAEAAEARSk/AqGQBCsgBAXppAFAAFzTea2F0cmFuIHRlc3QgcGt0",
     .description = "ipv4: lpm src lookup /24 . LPM_SRC_LOOKUP is required",
     .expectedReturnValue = "XDP_TX",
     .expectedOutputPacket =
         "AADerb6vAgAAAAAAht1gAAAAADMRQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAjBwACHmgXwAAzAABFAAArAAEAAEARSk/AqGQBCsgBAXppAFAAFzTea2F0cmFuIHRlc3QgcGt0"},
    // 4
    {// Ether(src="0x1", dst="0x2")/IP(src="192.168.200.1",
     // dst="10.200.1.1")/UDP(sport=31337, dport=80)/"katran test pkt"
     .inputPacket =
         "AgAAAAAAAQAAAAAACABFAAArAAEAAEAR5k7AqMgBCsgBAXppAFAAF9Dda2F0cmFuIHRlc3QgcGt0",
     .description = "ipv4: lpm miss. LPM_SRC_LOOKUP is required",
     .expectedReturnValue = "XDP_TX",
     .expectedOutputPacket =
         "AADerb6vAgAAAAAACABFAABHAAAAAEARWX8KAA0lCgAAA6F7F8AAMwAARQAAKwABAABAEeZOwKjIAQrIAQF6aQBQABfQ3WthdHJhbiB0ZXN0IHBrdA=="},
    // 5
    {// Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::2",
     // dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A")/"katran test
     // pkt"
     .inputPacket =
         "AgAAAAAAAQAAAAAAht1gAAAAACMGQPwAAAIAAAAAAAAAAAAAAAL8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1OAABrYXRyYW4gdGVzdCBwa3Q=",
     .description = "ipv6: lpm src lookup /64. LPM_SRC_LOOKUP is required",
     .expectedReturnValue = "XDP_TX",
     .expectedOutputPacket =
         "AADerb6vAgAAAAAAht1gAAAAAFMRQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAjBwAQemkXwABTAABgAAAAACMGQPwAAAIAAAAAAAAAAAAAAAL8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1OAABrYXRyYW4gdGVzdCBwa3Q="},
    // 6
    {// Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2307::1",
     // dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A")/"katran test
     // pkt"
     .inputPacket =
         "AgAAAAAAAQAAAAAAht1gAAAAACMGQPwAIwcAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgANpKAABrYXRyYW4gdGVzdCBwa3Q=",
     .description = "ipv6: lpm src lookup /32. LPM_SRC_LOOKUP is required",
     .expectedReturnValue = "XDP_TX",
     .expectedOutputPacket =
         "AADerb6vAgAAAAAAht1gAAAAAFMRQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAjBwAEemkXwABTAABgAAAAACMGQPwAIwcAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgANpKAABrYXRyYW4gdGVzdCBwa3Q="},
    // 7
    {// Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2308:1::1",
     // dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A")/"katran test
     // pkt"
     .inputPacket =
         "AgAAAAAAAQAAAAAAht1gAAAAACMGQPwAIwgAAQAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgANpIAABrYXRyYW4gdGVzdCBwa3Q=",
     .description = "ipv6: lpm miss. LPM_SRC_LOOKUP is required",
     .expectedReturnValue = "XDP_TX",
     .expectedOutputPacket =
         "AADerb6vAgAAAAAAht1gAAAAAFMRQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAABemkXwABTAABgAAAAACMGQPwAIwgAAQAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgANpIAABrYXRyYW4gdGVzdCBwa3Q="},
    // 8
    {// Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1",
     // dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A")/"katran test
     // pkt"
     .inputPacket =
         "AgAAAAAAAQAAAAAAht1gAAAAACMGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1PAABrYXRyYW4gdGVzdCBwa3Q=",
     .description = "ipv6: lpm cached flow. LPM_SRC_LOOKUP is required",
     .expectedReturnValue = "XDP_TX",
     .expectedOutputPacket =
         "AADerb6vAgAAAAAAht1gAAAAAFMRQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAADemkXwABTAABgAAAAACMGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1PAABrYXRyYW4gdGVzdCBwa3Q="},
};

} // namespace testing
} // namespace katran
