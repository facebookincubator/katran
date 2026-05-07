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

#include <gtest/gtest.h>

extern "C" {
#include <linux/ipv6.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
}

#include <folly/IPAddress.h>
#include <folly/io/IOBuf.h>

#include "katran/lib/KatranSimulatorUtils.h"

namespace katran {

// ---------------------------------------------------------------------------
// toV4String
// ---------------------------------------------------------------------------

TEST(KatranSimulatorUtilsTest, toV4StringRoundtrip) {
  auto addr = folly::IPAddressV4("1.2.3.4").toLong();
  EXPECT_EQ("1.2.3.4", KatranSimulatorUtils::toV4String(addr));
}

TEST(KatranSimulatorUtilsTest, toV4StringZero) {
  EXPECT_EQ("0.0.0.0", KatranSimulatorUtils::toV4String(0));
}

TEST(KatranSimulatorUtilsTest, toV4StringBroadcast) {
  auto addr = folly::IPAddressV4("255.255.255.255").toLong();
  EXPECT_EQ("255.255.255.255", KatranSimulatorUtils::toV4String(addr));
}

// ---------------------------------------------------------------------------
// toV6String
// ---------------------------------------------------------------------------

TEST(KatranSimulatorUtilsTest, toV6StringRoundtrip) {
  auto v6 = folly::IPAddressV6("2001:db8::1");
  auto bytes = v6.toBinary();
  EXPECT_EQ("2001:db8::1", KatranSimulatorUtils::toV6String(bytes.data()));
}

TEST(KatranSimulatorUtilsTest, toV6StringZero) {
  uint8_t zero16[16] = {0};
  EXPECT_EQ("::", KatranSimulatorUtils::toV6String(zero16));
}

// ---------------------------------------------------------------------------
// getPcktDst — error paths
// ---------------------------------------------------------------------------

TEST(KatranSimulatorUtilsTest, getPcktDstTooShortForEthdr) {
  auto pkt = folly::IOBuf::create(4);
  pkt->append(4);
  EXPECT_EQ("", KatranSimulatorUtils::getPcktDst(pkt));
}

// ---------------------------------------------------------------------------
// createPacketFromFlow — happy paths (also covers getPcktDst round-trip)
// ---------------------------------------------------------------------------

TEST(KatranSimulatorUtilsTest, createPacketV4TcpSizeAndProto) {
  KatranFlow flow{"192.168.1.1", "192.168.1.2", 5000, 80, IPPROTO_TCP};
  auto pkt = KatranSimulatorUtils::createPacketFromFlow(flow, 200);
  ASSERT_NE(nullptr, pkt);
  EXPECT_EQ(200u, pkt->computeChainDataLength());
  const auto* ehdr = reinterpret_cast<const struct ethhdr*>(pkt->data());
  EXPECT_EQ(htons(ETH_P_IP), ehdr->h_proto);
  const auto* iph = reinterpret_cast<const struct iphdr*>(
      pkt->data() + sizeof(struct ethhdr));
  EXPECT_EQ(IPPROTO_TCP, iph->protocol);
}

TEST(KatranSimulatorUtilsTest, createPacketV4TcpDst) {
  KatranFlow flow{"10.0.0.1", "10.0.0.2", 1234, 80, IPPROTO_TCP};
  auto pkt = KatranSimulatorUtils::createPacketFromFlow(flow, 200);
  ASSERT_NE(nullptr, pkt);
  EXPECT_EQ("10.0.0.2", KatranSimulatorUtils::getPcktDst(pkt));
}

TEST(KatranSimulatorUtilsTest, createPacketV4Udp) {
  KatranFlow flow{"10.0.0.1", "10.0.0.3", 4000, 53, IPPROTO_UDP};
  auto pkt = KatranSimulatorUtils::createPacketFromFlow(flow, 200);
  ASSERT_NE(nullptr, pkt);
  EXPECT_EQ("10.0.0.3", KatranSimulatorUtils::getPcktDst(pkt));
  const auto* iph = reinterpret_cast<const struct iphdr*>(
      pkt->data() + sizeof(struct ethhdr));
  EXPECT_EQ(IPPROTO_UDP, iph->protocol);
}

TEST(KatranSimulatorUtilsTest, createPacketV6TcpSizeAndProto) {
  KatranFlow flow{"fc00::1", "fc00::2", 5000, 80, IPPROTO_TCP};
  auto pkt = KatranSimulatorUtils::createPacketFromFlow(flow, 200);
  ASSERT_NE(nullptr, pkt);
  EXPECT_EQ(200u, pkt->computeChainDataLength());
  const auto* ehdr = reinterpret_cast<const struct ethhdr*>(pkt->data());
  EXPECT_EQ(htons(ETH_P_IPV6), ehdr->h_proto);
  const auto* ip6h = reinterpret_cast<const struct ipv6hdr*>(
      pkt->data() + sizeof(struct ethhdr));
  EXPECT_EQ(IPPROTO_TCP, ip6h->nexthdr);
}

TEST(KatranSimulatorUtilsTest, createPacketV6TcpDst) {
  KatranFlow flow{"fc00::1", "fc00::2", 1234, 80, IPPROTO_TCP};
  auto pkt = KatranSimulatorUtils::createPacketFromFlow(flow, 200);
  ASSERT_NE(nullptr, pkt);
  EXPECT_EQ("fc00::2", KatranSimulatorUtils::getPcktDst(pkt));
}

TEST(KatranSimulatorUtilsTest, createPacketV6Udp) {
  KatranFlow flow{"2001:db8::1", "2001:db8::2", 4000, 53, IPPROTO_UDP};
  auto pkt = KatranSimulatorUtils::createPacketFromFlow(flow, 200);
  ASSERT_NE(nullptr, pkt);
  EXPECT_EQ("2001:db8::2", KatranSimulatorUtils::getPcktDst(pkt));
}

// ---------------------------------------------------------------------------
// createPacketFromFlow — error paths
// ---------------------------------------------------------------------------

TEST(KatranSimulatorUtilsTest, createPacketMalformedSrc) {
  KatranFlow flow{"not_an_ip", "10.0.0.1", 1000, 80, IPPROTO_TCP};
  EXPECT_EQ(nullptr, KatranSimulatorUtils::createPacketFromFlow(flow, 200));
}

TEST(KatranSimulatorUtilsTest, createPacketMalformedDst) {
  KatranFlow flow{"10.0.0.1", "not_an_ip", 1000, 80, IPPROTO_TCP};
  EXPECT_EQ(nullptr, KatranSimulatorUtils::createPacketFromFlow(flow, 200));
}

TEST(KatranSimulatorUtilsTest, createPacketMismatchedFamily) {
  KatranFlow flow{"10.0.0.1", "fc00::2", 1000, 80, IPPROTO_TCP};
  EXPECT_EQ(nullptr, KatranSimulatorUtils::createPacketFromFlow(flow, 200));
}

TEST(KatranSimulatorUtilsTest, createPacketUnsupportedProto) {
  KatranFlow flow{"10.0.0.1", "10.0.0.2", 1000, 80, IPPROTO_ICMP};
  EXPECT_EQ(nullptr, KatranSimulatorUtils::createPacketFromFlow(flow, 200));
}

// ---------------------------------------------------------------------------
// TTL propagation
// ---------------------------------------------------------------------------

TEST(KatranSimulatorUtilsTest, defaultTtlIsWrittenToV4Header) {
  KatranFlow flow{"10.0.0.1", "10.0.0.2", 1000, 80, IPPROTO_TCP};
  auto pkt = KatranSimulatorUtils::createPacketFromFlow(flow, 200);
  ASSERT_NE(nullptr, pkt);
  const auto* iph = reinterpret_cast<const struct iphdr*>(
      pkt->data() + sizeof(struct ethhdr));
  EXPECT_EQ(64, iph->ttl);
}

TEST(KatranSimulatorUtilsTest, customTtlIsWrittenToV6Header) {
  KatranFlow flow{"fc00::1", "fc00::2", 1000, 80, IPPROTO_TCP};
  auto pkt = KatranSimulatorUtils::createPacketFromFlow(flow, 200, /*ttl=*/128);
  ASSERT_NE(nullptr, pkt);
  const auto* ip6h = reinterpret_cast<const struct ipv6hdr*>(
      pkt->data() + sizeof(struct ethhdr));
  EXPECT_EQ(128, ip6h->hop_limit);
}

} // namespace katran
