// @nolint

/* Copyright (C) 2026-present, Meta Platforms, Inc. and affiliates.
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
#include <algorithm>
#include <string>
#include <vector>
#include "katran/lib/testing/tools/PacketAttributes.h"

namespace katran {
namespace testing {

/**
 * Fixtures for GUE_PTB_RELAY: ICMP packet too big messages sent by a hop
 * between katran and a real, quoting the GUE packet katran sent there.
 *
 * Each PTB quotes a client flow whose real and GUE source port are taken from
 * the forwarded packets in KatranGueTestFixtures.h, KatranJumboTestFixtures.h
 * and KatranCidrVipTestFixtures.h:
 *  - fc00:2::1:31337 -> fc00:1::1:80/tcp goes to fc00::3, sport 31337
 *  - 192.168.1.1:31337 -> 10.200.1.3:80/tcp goes to fc00::1, sport 31592
 *  - 192.0.2.1:31337 -> 10.200.1.1:80/udp goes to 10.0.0.1, sport 27515
 *  - 192.168.1.1:31337 -> 10.200.1.4:42/tcp, a vip hashing on the dst port
 *    only, goes to 10.0.0.2, sport 27002
 *  - 192.168.1.42:31337 -> 10.200.1.5:443/udp, a quic vip, goes to 10.0.0.2,
 *    sport 26704 by ch, and to fc00::1, sport 31555 by connection id
 *  - fc00:2::1:31337 -> fc00:1::100:80/tcp goes to fc00::1 and
 *    fc00:2::1:31337 -> fc00:2::100:443/tcp to fc00::4, both sport 31337, on
 *    the cidr vips of prepareCidrVipLbData
 * from katran's GUE sources fc00:2307::1337 and 10.0.13.37.
 *
 * The relayed PTB announces the reported mtu less the GUE overhead (48 bytes
 * for an IPv6 outer header, 28 for IPv4), clamped to the flavor's own limit,
 * MAX_PCKT_SIZE less the ethernet header, and to at least 1280 (IPv6) or 576
 * (IPv4), and
 * quotes as much of the client's packet as the PTBs katran generates itself.
 * PTBs which are not relayed take the regular path, which passes them.
 */
using TestFixture = std::vector<PacketAttributes>;

constexpr uint16_t kGuePort = 9886;

// largest packet the jumbo origin flavors forward: MAX_PCKT_SIZE of
// origin_jumbo_defines in katran/lib/bpf/BUCK less the ethernet header. it
// follows that define
constexpr uint16_t kJumboOriginMtu = 4952;

// first bytes of a client's packet, as quoted by the hop. it claims its full
// length in its ip header
inline std::vector<uint8_t> guePtbQuote(
    const PacketBuilder& clientPacket,
    size_t quotedBytes) {
  auto bytes = clientPacket.buildAsBytes();
  bytes.resize(std::min(bytes.size(), quotedBytes));
  return bytes;
}

// fc00:2::1:31337 -> vip:dport/tcp
inline PacketBuilder guePtbV6Client(
    size_t payloadSize = 1500,
    const std::string& vip = "fc00:1::1",
    uint16_t dport = 80) {
  return PacketBuilder::newPacket()
      .IPv6("fc00:2::1", vip)
      .TCP(31337, dport, 0, 0, 8192, TH_ACK)
      .payload(std::string(payloadSize, 'k'));
}

// 192.168.1.1:31337 -> 10.200.1.3:80/tcp
inline PacketBuilder guePtbV4InV6Client() {
  return PacketBuilder::newPacket()
      .IPv4("192.168.1.1", "10.200.1.3")
      .TCP(31337, 80, 0, 0, 8192, TH_ACK)
      .payload(std::string(1500, 'k'));
}

// 192.0.2.1:31337 -> 10.200.1.1:80/udp
inline PacketBuilder guePtbV4Client() {
  return PacketBuilder::newPacket()
      .IPv4("192.0.2.1", "10.200.1.1")
      .UDP(31337, 80)
      .payload(std::string(1500, 'k'));
}

// 192.168.1.1:31337 -> 10.200.1.4:42/tcp
inline PacketBuilder guePtbDportHashClient() {
  return PacketBuilder::newPacket()
      .IPv4("192.168.1.1", "10.200.1.4")
      .TCP(31337, 42, 0, 0, 8192, TH_ACK)
      .payload(std::string(1500, 'k'));
}

// 192.168.1.42:31337 -> 10.200.1.5:443/udp
inline PacketBuilder guePtbQuicClient() {
  return PacketBuilder::newPacket()
      .IPv4("192.168.1.42", "10.200.1.5")
      .UDP(31337, 443)
      .payload(std::string(1500, 'k'));
}

// a hop's ICMPv6 PTB for a GUE packet katran sent from src to real, quoting
// as much as fits in 1280 bytes unless quotedBytes is set. the hop sends it to
// katran's GUE source unless to is set
inline PacketBuilder guePtbFromV6Hop(
    uint16_t mtu,
    const PacketBuilder& clientPacket,
    const std::string& real,
    uint16_t sport,
    const std::string& src = "fc00:2307::1337",
    uint16_t dport = kGuePort,
    size_t quotedBytes = 1280 - 40 - 8 - 40 - 8,
    const std::string& to = "fc00:2307::1337") {
  return PacketBuilder::newPacket()
      .Eth("0x1", "0x2")
      .IPv6("fc00:3::1", to)
      .ICMPv6(ICMPv6Header::PACKET_TOO_BIG, 0, 0, mtu)
      .IPv6(src, real)
      .UDP(sport, dport)
      .payload(guePtbQuote(clientPacket, quotedBytes));
}

// a hop's ICMPv4 fragmentation needed for a GUE packet katran sent to real,
// quoting as much as fits in 576 bytes unless quotedBytes is set. the hop sends
// it to katran's GUE source unless to is set
inline PacketBuilder guePtbFromV4Hop(
    uint16_t mtu,
    const PacketBuilder& clientPacket,
    const std::string& real = "10.0.0.1",
    uint16_t sport = 27515,
    size_t quotedBytes = 576 - 20 - 8 - 20 - 8,
    const std::string& to = "10.0.13.37") {
  return PacketBuilder::newPacket()
      .Eth("0x1", "0x2")
      .IPv4("10.0.0.254", to)
      .ICMP(ICMPv4Header::DEST_UNREACH, ICMPv4Header::FRAG_NEEDED, 0, mtu)
      .IPv4("10.0.13.37", real, 64, 0, 0)
      .UDP(sport, kGuePort)
      .payload(guePtbQuote(clientPacket, quotedBytes));
}

inline PacketBuilder relayedV6Ptb(
    uint32_t mtu,
    const PacketBuilder& clientPacket,
    const std::string& vip = "fc00:1::1") {
  return PacketBuilder::newPacket()
      .Eth("02:00:00:00:00:00", "01:00:00:00:00:00")
      .IPv6(vip, "fc00:2::1")
      .ICMPv6PacketTooBig(
          mtu,
          PacketBuilder::newPacket().payload(clientPacket.buildAsBytes()));
}

inline PacketBuilder relayedV4Ptb(
    uint16_t mtu,
    const std::string& vip,
    const std::string& client,
    const PacketBuilder& clientPacket) {
  return PacketBuilder::newPacket()
      .Eth("02:00:00:00:00:00", "01:00:00:00:00:00")
      .IPv4(vip, client, 64, 0, 0)
      .ICMP(
          ICMPv4Header::DEST_UNREACH,
          ICMPv4Header::FRAG_NEEDED,
          mtu,
          PacketBuilder::newPacket().payload(clientPacket.buildAsBytes()));
}

// a PTB the relay passes on unchanged
inline PacketAttributes guePtbPassed(
    const std::string& description,
    const PacketBuilder& ptb) {
  return {
      .description = description,
      .expectedReturnValue = "XDP_PASS",
      .inputPacketBuilder = ptb,
      .expectedOutputPacketBuilder = ptb};
}

// run on a jumbo origin flavor after prepareLbData
const TestFixture guePtbRelayTestFixtures = {
    {.description = "ICMPv6 PTB for a v6 client is relayed",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder =
         guePtbFromV6Hop(1500, guePtbV6Client(), "fc00::3", 31337),
     .expectedOutputPacketBuilder = relayedV6Ptb(1452, guePtbV6Client())},
    {.description = "ICMPv6 PTB for a v4 client is relayed as frag needed",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder =
         guePtbFromV6Hop(1500, guePtbV4InV6Client(), "fc00::1", 31592),
     .expectedOutputPacketBuilder = relayedV4Ptb(
         1452, "10.200.1.3", "192.168.1.1", guePtbV4InV6Client())},
    {.description = "ICMPv4 frag needed for a v4 client is relayed",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = guePtbFromV4Hop(1500, guePtbV4Client()),
     .expectedOutputPacketBuilder =
         relayedV4Ptb(1472, "10.200.1.1", "192.0.2.1", guePtbV4Client())},
    {.description = "mtu below the IPv6 minimum is raised to 1280",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder =
         guePtbFromV6Hop(1300, guePtbV6Client(), "fc00::3", 31337),
     .expectedOutputPacketBuilder = relayedV6Ptb(1280, guePtbV6Client())},
    {.description = "mtu below the IPv4 minimum is raised to 576",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = guePtbFromV4Hop(500, guePtbV4Client()),
     .expectedOutputPacketBuilder =
         relayedV4Ptb(576, "10.200.1.1", "192.0.2.1", guePtbV4Client())},
    {.description = "mtu above the jumbo limit is capped to it",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder =
         guePtbFromV6Hop(
             kJumboOriginMtu + 1000,
             guePtbV6Client(kJumboOriginMtu),
             "fc00::3",
             31337),
     .expectedOutputPacketBuilder =
         relayedV6Ptb(kJumboOriginMtu, guePtbV6Client(kJumboOriginMtu))},
    {.description = "PTB for a vip hashing on the dst port only is relayed",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder =
         guePtbFromV4Hop(1500, guePtbDportHashClient(), "10.0.0.2", 27002),
     .expectedOutputPacketBuilder = relayedV4Ptb(
         1472, "10.200.1.4", "192.168.1.1", guePtbDportHashClient())},
    {.description = "PTB for a quic flow routed by ch is relayed",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder =
         guePtbFromV4Hop(1500, guePtbQuicClient(), "10.0.0.2", 26704),
     .expectedOutputPacketBuilder = relayedV4Ptb(
         1472, "10.200.1.5", "192.168.1.42", guePtbQuicClient())},
    {.description = "PTB for a quic flow routed by connection id is relayed",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder =
         guePtbFromV6Hop(1500, guePtbQuicClient(), "fc00::1", 31555),
     .expectedOutputPacketBuilder = relayedV4Ptb(
         1452, "10.200.1.5", "192.168.1.42", guePtbQuicClient())},
    guePtbPassed(
        "PTB whose mtu fits the client's packet is not relayed",
        guePtbFromV6Hop(4000, guePtbV6Client(), "fc00::3", 31337)),
    {.description = "PTB quoting a real other than the ch one is relayed",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder =
         guePtbFromV4Hop(1500, guePtbV4Client(), "10.0.0.2", 27515),
     .expectedOutputPacketBuilder =
         relayedV4Ptb(1472, "10.200.1.1", "192.0.2.1", guePtbV4Client())},
    {.description = "PTB quoting a real tcp server id routing picked is relayed",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder =
         guePtbFromV6Hop(1500, guePtbV6Client(), "fc00::1", 31337),
     .expectedOutputPacketBuilder = relayedV6Ptb(1452, guePtbV6Client())},
    guePtbPassed(
        "PTB for a packet not sourced by katran is not relayed",
        guePtbFromV6Hop(
            1500, guePtbV6Client(), "fc00::3", 31337, "fc00:2307::2")),
    guePtbPassed(
        "ICMPv6 PTB sent to a vip rather than katran's GUE source is not "
        "relayed",
        guePtbFromV6Hop(
            1500,
            guePtbV6Client(),
            "fc00::3",
            31337,
            "fc00:2307::1337",
            kGuePort,
            1280 - 40 - 8 - 40 - 8,
            "fc00:1::1")),
    guePtbPassed(
        "ICMPv4 frag needed sent to a vip rather than katran's GUE source is "
        "not relayed",
        guePtbFromV4Hop(
            1500,
            guePtbV4Client(),
            "10.0.0.1",
            27515,
            576 - 20 - 8 - 20 - 8,
            "10.200.1.1")),
    guePtbPassed(
        "PTB for a non GUE udp packet is not relayed",
        guePtbFromV6Hop(
            1500, guePtbV6Client(), "fc00::3", 31337, "fc00:2307::1337", 6080)),
    guePtbPassed(
        "ICMPv4 frag needed quoting only the GUE udp header is not relayed",
        guePtbFromV4Hop(1500, guePtbV4Client(), "10.0.0.1", 27515, 0)),
    guePtbPassed(
        "ICMPv6 PTB quoting too little of the client's packet is not relayed",
        guePtbFromV6Hop(
            1500,
            guePtbV6Client(),
            "fc00::3",
            31337,
            "fc00:2307::1337",
            kGuePort,
            100)),
    guePtbPassed(
        "PTB for a client's packet which is neither tcp nor udp is not relayed",
        guePtbFromV6Hop(
            1500,
            PacketBuilder::newPacket()
                .IPv6("fc00:2::1", "fc00:1::1")
                .ICMPv6()
                .payload(std::string(1500, 'k')),
            "fc00::3",
            31337)),
    guePtbPassed(
        "PTB for a client's packet with an extension header is not relayed",
        guePtbFromV6Hop(
            1500,
            PacketBuilder::newPacket()
                .IPv6(
                    "fc00:2::1",
                    "fc00:1::1",
                    64,
                    0,
                    0,
                    PacketBuilder::IPV6_NH_FRAGMENT)
                .TCP(31337, 80, 0, 0, 8192, TH_ACK)
                .payload(std::string(1500, 'k')),
            "fc00::3",
            31337)),
};

// run on a flavor with CIDR_VIP after prepareCidrVipLbData. its mtu limit is
// the default 1500
const TestFixture guePtbRelayCidrVipTestFixtures = {
    {.description = "PTB for a flow to a cidr vip of all ports is relayed",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = guePtbFromV6Hop(
         1500, guePtbV6Client(1500, "fc00:1::100"), "fc00::1", 31337),
     .expectedOutputPacketBuilder = relayedV6Ptb(
         1452, guePtbV6Client(1500, "fc00:1::100"), "fc00:1::100")},
    {.description = "PTB for a flow to a port specific cidr vip is relayed",
     .expectedReturnValue = "XDP_TX",
     .inputPacketBuilder = guePtbFromV6Hop(
         1500, guePtbV6Client(1500, "fc00:2::100", 443), "fc00::4", 31337),
     .expectedOutputPacketBuilder = relayedV6Ptb(
         1452, guePtbV6Client(1500, "fc00:2::100", 443), "fc00:2::100")},
};

} // namespace testing
} // namespace katran
