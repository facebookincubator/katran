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

#include "katran/lib/testing/PacketBuilder.h"

#include <arpa/inet.h>
#include <folly/String.h>
#include <folly/base64.h>
#include <glog/logging.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace katran {
namespace testing {

static constexpr uint16_t DEFAULT_TCP_WINDOW = 8192;
static constexpr uint8_t DEFAULT_IPV6_HOP_LIMIT = 64;
static constexpr uint32_t IPV6_VERSION_SHIFT = 28;
static constexpr uint32_t IPV6_TRAFFIC_CLASS_SHIFT = 20;
static constexpr uint32_t IPV6_FLOW_LABEL_MASK = 0xFFFFF;

static constexpr size_t MAC_ADDRESS_LENGTH = 6;
static constexpr uint8_t IPV4_MIN_HEADER_LENGTH = 5; // 5 * 4 = 20 bytes
static constexpr uint8_t TCP_MIN_HEADER_LENGTH = 5; // 5 * 4 = 20 bytes

static constexpr size_t IPV4_PSEUDO_HEADER_SIZE = 12;
static constexpr size_t IPV6_PSEUDO_HEADER_SIZE = 40;

static constexpr uint16_t UDP_IPV6_ZERO_CHECKSUM_REPLACEMENT = 0xFFFF;

PacketBuilder PacketBuilder::newPacket() {
  return PacketBuilder();
}

PacketBuilder& PacketBuilder::Eth(
    const std::string& src,
    const std::string& dst) {
  if (!isValidMacAddress(src)) {
    throw std::invalid_argument("Invalid source MAC address: " + src);
  }
  if (!isValidMacAddress(dst)) {
    throw std::invalid_argument("Invalid destination MAC address: " + dst);
  }

  headerStack_.push_back(std::make_shared<EthernetHeader>(src, dst));
  return *this;
}

PacketBuilder& PacketBuilder::IPv4(
    const std::string& src,
    const std::string& dst,
    uint8_t ttl,
    uint8_t tos,
    uint16_t id,
    uint16_t flags) {
  if (!isValidIPv4Address(src)) {
    throw std::invalid_argument("Invalid source IPv4 address: " + src);
  }
  if (!isValidIPv4Address(dst)) {
    throw std::invalid_argument("Invalid destination IPv4 address: " + dst);
  }

  headerStack_.push_back(
      std::make_shared<IPv4Header>(src, dst, ttl, tos, id, flags));
  return *this;
}

PacketBuilder& PacketBuilder::IPv6(
    const std::string& src,
    const std::string& dst,
    uint8_t hopLimit,
    uint8_t trafficClass,
    uint32_t flowLabel) {
  if (!isValidIPv6Address(src)) {
    throw std::invalid_argument("Invalid source IPv6 address: " + src);
  }
  if (!isValidIPv6Address(dst)) {
    throw std::invalid_argument("Invalid destination IPv6 address: " + dst);
  }

  headerStack_.push_back(std::make_shared<IPv6Header>(
      src, dst, hopLimit, trafficClass, flowLabel));
  return *this;
}

PacketBuilder& PacketBuilder::UDP(uint16_t sport, uint16_t dport) {
  if (!isValidPort(sport)) {
    throw std::invalid_argument(
        "Invalid source port: " + std::to_string(sport));
  }
  if (!isValidPort(dport)) {
    throw std::invalid_argument(
        "Invalid destination port: " + std::to_string(dport));
  }

  headerStack_.push_back(std::make_shared<UDPHeader>(sport, dport));
  return *this;
}

PacketBuilder& PacketBuilder::TCP(
    uint16_t sport,
    uint16_t dport,
    uint32_t seq,
    uint32_t ackSeq,
    uint16_t window,
    uint8_t flags) {
  if (!isValidPort(sport)) {
    throw std::invalid_argument(
        "Invalid source port: " + std::to_string(sport));
  }
  if (!isValidPort(dport)) {
    throw std::invalid_argument(
        "Invalid destination port: " + std::to_string(dport));
  }

  headerStack_.push_back(
      std::make_shared<TCPHeader>(sport, dport, seq, ackSeq, window, flags));
  return *this;
}

PacketBuilder& PacketBuilder::payload(const std::string& data) {
  std::vector<uint8_t> payloadData(data.begin(), data.end());
  return payload(payloadData);
}

PacketBuilder& PacketBuilder::payload(const std::vector<uint8_t>& data) {
  if (data.empty()) {
    LOG(INFO) << "Adding empty payload";
  }

  headerStack_.push_back(std::make_shared<PayloadHeader>(data));
  return *this;
}

PacketBuilder::PacketResult PacketBuilder::build() {
  auto binaryPacket = buildBinaryPacket();

  PacketResult result;
  result.base64Packet = bytesToBase64(binaryPacket);
  result.scapyCommand = generateScapyCommand();
  result.packetSize = binaryPacket.size();

  return result;
}

std::vector<uint8_t> PacketBuilder::buildBinaryPacket() {
  if (headerStack_.empty()) {
    throw std::invalid_argument("Cannot build packet: no headers added");
  }

  std::vector<uint8_t> packet;

  // Update protocol fields based on next headers
  for (size_t i = 0; i < headerStack_.size(); ++i) {
    auto& entry = headerStack_[i];

    if (i + 1 < headerStack_.size()) {
      auto nextType = headerStack_[i + 1]->getType();
      entry->updateForNextHeader(nextType);
    }
  }

  // Build packet from the end (payload first) to calculate lengths correctly
  for (int i = static_cast<int>(headerStack_.size()) - 1; i >= 0; --i) {
    headerStack_[i]->serialize(static_cast<size_t>(i), headerStack_, packet);
  }

  return packet;
}

std::string PacketBuilder::generateScapyCommand() {
  std::string command;

  for (const auto& entry : headerStack_) {
    if (!command.empty()) {
      command += "/";
    }
    command += entry->generateScapyCommand();
  }

  return command;
}

std::string PacketBuilder::bytesToBase64(const std::vector<uint8_t>& bytes) {
  return folly::base64Encode(folly::StringPiece(
      reinterpret_cast<const char*>(bytes.data()), bytes.size()));
}

bool PacketBuilder::isValidMacAddress(const std::string& mac) {
  // Handle "0x" format
  if (mac.find("0x") == 0) {
    return mac.length() >= 3 && mac.length() <= 18; // 0x1 to 0xffffffffffff
  }

  // Handle standard MAC format (xx:xx:xx:xx:xx:xx)
  if (mac.find(':') != std::string::npos) {
    // Simple validation: check format xx:xx:xx:xx:xx:xx
    std::vector<folly::StringPiece> parts;
    folly::split(':', mac, parts);
    if (parts.size() != 6) {
      return false;
    }

    for (const auto& part : parts) {
      if (part.size() != 2) {
        return false;
      }
      for (char c : part) {
        if (!std::isxdigit(c)) {
          return false;
        }
      }
    }
    return true;
  }

  return false;
}

bool PacketBuilder::isValidIPv4Address(const std::string& ip) {
  struct in_addr addr;
  return inet_aton(ip.c_str(), &addr) != 0;
}

bool PacketBuilder::isValidIPv6Address(const std::string& ip) {
  struct in6_addr addr;
  return inet_pton(AF_INET6, ip.c_str(), &addr) == 1;
}

bool PacketBuilder::isValidPort(uint16_t port) {
  // Port 0 is reserved and generally not valid for most use cases
  // However, for testing purposes, we might want to allow it
  // So we'll only reject it with a warning rather than throwing
  if (port == 0) {
    LOG(WARNING) << "Using port 0 which is reserved";
  }

  // All other ports (1-65535) are valid since uint16_t constrains the range
  return true;
}

// EthernetHeader implementation
EthernetHeader::EthernetHeader(const std::string& src, const std::string& dst) {
  static_assert(
      sizeof(eth_.h_source) == MAC_ADDRESS_LENGTH,
      "Source MAC field size mismatch");
  static_assert(
      sizeof(eth_.h_dest) == MAC_ADDRESS_LENGTH,
      "Destination MAC field size mismatch");

  std::memset(&eth_, 0, sizeof(eth_));

  auto srcBytes = macStringToBytes(src);
  auto dstBytes = macStringToBytes(dst);

  if (srcBytes.size() != MAC_ADDRESS_LENGTH ||
      dstBytes.size() != MAC_ADDRESS_LENGTH) {
    throw std::invalid_argument("Invalid MAC address length");
  }

  std::memcpy(eth_.h_source, srcBytes.data(), MAC_ADDRESS_LENGTH);
  std::memcpy(eth_.h_dest, dstBytes.data(), MAC_ADDRESS_LENGTH);
  eth_.h_proto = 0; // Will be updated based on next header
}

void EthernetHeader::serialize(
    size_t headerIndex,
    const std::vector<std::shared_ptr<HeaderEntry>>& headerStack,
    std::vector<uint8_t>& packet) {
  const uint8_t* ethBytes = reinterpret_cast<const uint8_t*>(&eth_);
  packet.insert(packet.begin(), ethBytes, ethBytes + sizeof(struct ethhdr));
}

std::string EthernetHeader::generateScapyCommand() const {
  std::stringstream srcMac, dstMac;
  srcMac << std::hex << std::setfill('0');
  dstMac << std::hex << std::setfill('0');

  for (int i = 0; i < 6; ++i) {
    if (i > 0) {
      srcMac << ":";
      dstMac << ":";
    }
    srcMac << std::setw(2) << static_cast<unsigned>(eth_.h_source[i]);
    dstMac << std::setw(2) << static_cast<unsigned>(eth_.h_dest[i]);
  }

  return "Ether(src='" + srcMac.str() + "', dst='" + dstMac.str() + "')";
}

void EthernetHeader::updateForNextHeader(Type nextHeaderType) {
  switch (nextHeaderType) {
    case IPV4:
      eth_.h_proto = htons(ETH_P_IP);
      break;
    case IPV6:
      eth_.h_proto = htons(ETH_P_IPV6);
      break;
    default:
      VLOG(2) << "Unhandled next header type: "
              << static_cast<int>(nextHeaderType);
      break;
  }
}

std::vector<uint8_t> EthernetHeader::macStringToBytes(
    const std::string& macStr) {
  std::vector<uint8_t> bytes;

  // Handle simple format like "0x1" -> 01:00:00:00:00:00
  if (macStr.find("0x") == 0) {
    bytes.resize(MAC_ADDRESS_LENGTH, 0);
    try {
      uint64_t macVal = std::stoull(macStr, nullptr, 16);
      bytes[0] = macVal & 0xFF;
      bytes[1] = (macVal >> 8) & 0xFF;
      bytes[2] = (macVal >> 16) & 0xFF;
      bytes[3] = (macVal >> 24) & 0xFF;
      bytes[4] = (macVal >> 32) & 0xFF;
      bytes[5] = (macVal >> 40) & 0xFF;
    } catch (...) {
      bytes.assign(6, 0);
    }
  } else if (macStr.find(':') != std::string::npos) {
    // Handle standard MAC format like "01:02:03:04:05:06"
    bytes.resize(6, 0);
    std::vector<folly::StringPiece> parts;
    folly::split(':', macStr, parts);
    if (parts.size() == 6) {
      try {
        for (size_t i = 0; i < 6; ++i) {
          bytes[i] =
              static_cast<uint8_t>(std::stoul(parts[i].str(), nullptr, 16));
        }
      } catch (...) {
        bytes.assign(6, 0);
      }
    } else {
      bytes.assign(6, 0);
    }
  } else {
    bytes.resize(6, 0);
  }

  return bytes;
}

// IPv4Header implementation
IPv4Header::IPv4Header(
    const std::string& src,
    const std::string& dst,
    uint8_t ttl,
    uint8_t tos,
    uint16_t id,
    uint16_t flags) {
  static_assert(
      sizeof(ip_.saddr) == 4, "IPv4 source address field size mismatch");
  static_assert(
      sizeof(ip_.daddr) == 4, "IPv4 destination address field size mismatch");

  std::memset(&ip_, 0, sizeof(ip_));

  struct in_addr srcAddr {
  }, dstAddr{};
  if (inet_aton(src.c_str(), &srcAddr) == 0) {
    LOG(ERROR) << "Invalid IPv4 source address: " << src;
  }
  if (inet_aton(dst.c_str(), &dstAddr) == 0) {
    LOG(ERROR) << "Invalid IPv4 destination address: " << dst;
  }

  ip_.version = 4;
  ip_.ihl = IPV4_MIN_HEADER_LENGTH; // 4*5=20 bytes IP header length
  ip_.tos = tos;
  ip_.tot_len = 0; // Will be calculated in serialize()
  ip_.id = htons(id);
  ip_.frag_off = htons(flags);
  ip_.ttl = ttl;
  ip_.protocol = 0; // Will be updated based on next header
  ip_.check = 0; // Will be calculated in serialize()
  ip_.saddr = srcAddr.s_addr;
  ip_.daddr = dstAddr.s_addr;
}

void IPv4Header::serialize(
    size_t headerIndex,
    const std::vector<std::shared_ptr<HeaderEntry>>& headerStack,
    std::vector<uint8_t>& packet) {
  auto ip = ip_;

  // Set total length based on current packet size (which contains the payload)
  ip.tot_len = htons(sizeof(struct iphdr) + packet.size());

  // Calculate checksum
  ip.check = 0;
  const uint8_t* ipBytes = reinterpret_cast<const uint8_t*>(&ip);
  std::vector<uint8_t> ipForChecksum(ipBytes, ipBytes + sizeof(struct iphdr));
  uint16_t checksum = calculateChecksum(ipForChecksum);
  ip.check = htons(checksum);

  const uint8_t* finalIpBytes = reinterpret_cast<const uint8_t*>(&ip);
  packet.insert(
      packet.begin(), finalIpBytes, finalIpBytes + sizeof(struct iphdr));
}

std::string IPv4Header::generateScapyCommand() const {
  struct in_addr srcAddr {
  }, dstAddr{};
  srcAddr.s_addr = ip_.saddr;
  dstAddr.s_addr = ip_.daddr;

  std::string srcIp = inet_ntoa(srcAddr);
  std::string dstIp = inet_ntoa(dstAddr);

  std::string command = "IP(src='" + srcIp + "', dst='" + dstIp + "'";

  // Add ToS if non-zero
  if (ip_.tos != 0) {
    command += ", tos=" + std::to_string(ip_.tos);
  }

  command += ")";
  return command;
}

void IPv4Header::updateForNextHeader(Type nextHeaderType) {
  switch (nextHeaderType) {
    case UDP_HEADER:
      ip_.protocol = IPPROTO_UDP;
      break;
    case TCP_HEADER:
      ip_.protocol = IPPROTO_TCP;
      break;
    case IPV6:
      ip_.protocol = IPPROTO_IPV6;
      break;
    case IPV4:
      ip_.protocol = IPPROTO_IPIP; // IPv4-in-IPv4 tunneling
      break;
    default:
      VLOG(2) << "Unknown next header type: "
              << static_cast<int>(nextHeaderType);
      break;
  }
}

uint16_t IPv4Header::calculateChecksum(
    const std::vector<uint8_t>& data,
    size_t start,
    size_t len) {
  if (len == 0) {
    len = data.size() - start;
  }

  uint32_t sum = 0;

  // Sum all 16-bit words in network byte order
  for (size_t i = start; i < start + len - 1; i += 2) {
    uint16_t word = (static_cast<uint16_t>(data[i]) << 8) +
        static_cast<uint16_t>(data[i + 1]);
    sum += word;
  }

  // Add odd byte if present (pad with zero)
  if (len % 2 == 1) {
    sum += static_cast<uint16_t>(data[start + len - 1]) << 8;
  }

  // Add carry bits
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  return static_cast<uint16_t>(~sum);
}

// IPv6Header implementation
IPv6Header::IPv6Header(
    const std::string& src,
    const std::string& dst,
    uint8_t hopLimit,
    uint8_t trafficClass,
    uint32_t flowLabel) {
  static_assert(
      sizeof(ip6_.ip6_src) == 16, "IPv6 source address field size mismatch");
  static_assert(
      sizeof(ip6_.ip6_dst) == 16,
      "IPv6 destination address field size mismatch");

  std::memset(&ip6_, 0, sizeof(ip6_));

  if (flowLabel > IPV6_FLOW_LABEL_MASK) {
    LOG(WARNING) << "Flow label " << flowLabel
                 << " exceeds 20-bit limit, truncating";
    flowLabel &= IPV6_FLOW_LABEL_MASK;
  }

  uint32_t version_tc_fl = (6U << IPV6_VERSION_SHIFT) |
      ((uint32_t)trafficClass << IPV6_TRAFFIC_CLASS_SHIFT) |
      (flowLabel & IPV6_FLOW_LABEL_MASK);
  ip6_.ip6_flow = htonl(version_tc_fl);
  ip6_.ip6_plen = 0; // Will be calculated in serialize()
  ip6_.ip6_nxt = 0; // Will be updated based on next header
  ip6_.ip6_hlim = hopLimit;

  struct in6_addr src_addr {
  }, dst_addr{};
  if (inet_pton(AF_INET6, src.c_str(), &src_addr) != 1) {
    LOG(ERROR) << "Invalid IPv6 source address: " << src;
  }
  if (inet_pton(AF_INET6, dst.c_str(), &dst_addr) != 1) {
    LOG(ERROR) << "Invalid IPv6 destination address: " << dst;
  }

  ip6_.ip6_src = src_addr;
  ip6_.ip6_dst = dst_addr;
}

void IPv6Header::serialize(
    size_t headerIndex,
    const std::vector<std::shared_ptr<HeaderEntry>>& headerStack,
    std::vector<uint8_t>& packet) {
  auto ip6 = ip6_;

  // Set payload length based on current packet size (which contains the
  // payload)
  ip6.ip6_plen = htons(packet.size());

  const uint8_t* ip6Bytes = reinterpret_cast<const uint8_t*>(&ip6);
  packet.insert(packet.begin(), ip6Bytes, ip6Bytes + sizeof(struct ip6_hdr));
}

std::string IPv6Header::generateScapyCommand() const {
  char srcStr[INET6_ADDRSTRLEN], dstStr[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, &ip6_.ip6_src, srcStr, INET6_ADDRSTRLEN);
  inet_ntop(AF_INET6, &ip6_.ip6_dst, dstStr, INET6_ADDRSTRLEN);

  std::string command = "IPv6(src='" + std::string(srcStr) + "', dst='" +
      std::string(dstStr) + "'";
  if (ip6_.ip6_hlim != DEFAULT_IPV6_HOP_LIMIT) {
    command += ", hlim=" + std::to_string(ip6_.ip6_hlim);
  }
  command += ")";
  return command;
}

void IPv6Header::updateForNextHeader(Type nextHeaderType) {
  switch (nextHeaderType) {
    case UDP_HEADER:
      ip6_.ip6_nxt = IPPROTO_UDP;
      break;
    case TCP_HEADER:
      ip6_.ip6_nxt = IPPROTO_TCP;
      break;
    case IPV6:
      ip6_.ip6_nxt = IPPROTO_IPV6; // IPv6-in-IPv6 tunneling
      break;
    case IPV4:
      ip6_.ip6_nxt = IPPROTO_IPIP; // IPv4-in-IPv6 tunneling
      break;
    default:
      VLOG(2) << "Unknown next header type: "
              << static_cast<int>(nextHeaderType);
      break;
  }
}

// UDPHeader implementation
UDPHeader::UDPHeader(uint16_t sport, uint16_t dport) {
  std::memset(&udp_, 0, sizeof(udp_));
  udp_.source = htons(sport);
  udp_.dest = htons(dport);
  udp_.len = 0; // Will be calculated in serialize()
  udp_.check = 0; // Will be calculated in serialize()
}

void UDPHeader::serialize(
    size_t headerIndex,
    const std::vector<std::shared_ptr<HeaderEntry>>& headerStack,
    std::vector<uint8_t>& packet) {
  auto udp = udp_;

  // Set UDP length based on current packet size (which contains the payload)
  udp.len = htons(sizeof(struct udphdr) + packet.size());

  // Find IP header for checksum calculation
  struct iphdr ipv4Header {};
  struct ip6_hdr ipv6Header {};
  findIPHeaderForChecksum(headerIndex, headerStack, &ipv4Header, &ipv6Header);

  // Calculate checksum using the already-built payload in packet
  if (ipv4Header.version == 4) {
    udp.check = htons(calculateUdpChecksum(udp, ipv4Header, packet));
  } else if ((ntohl(ipv6Header.ip6_flow) >> 28) == 6) {
    udp.check = htons(calculateUdpChecksumV6(udp, ipv6Header, packet));
  } else {
    LOG(WARNING) << "No IPv4/IPv6 header found for UDP checksum calculation, "
                 << "checksum will be 0";
  }

  const uint8_t* udpBytes = reinterpret_cast<const uint8_t*>(&udp);
  packet.insert(packet.begin(), udpBytes, udpBytes + sizeof(struct udphdr));
}

std::string UDPHeader::generateScapyCommand() const {
  uint16_t sport = ntohs(udp_.source);
  uint16_t dport = ntohs(udp_.dest);
  return "UDP(sport=" + std::to_string(sport) +
      ", dport=" + std::to_string(dport) + ")";
}

void UDPHeader::findIPHeaderForChecksum(
    size_t headerIndex,
    const std::vector<std::shared_ptr<HeaderEntry>>& headerStack,
    struct iphdr* ipv4Header,
    struct ip6_hdr* ipv6Header) {
  // Find the most recent IP header before the current header
  for (int i = static_cast<int>(headerIndex) - 1; i >= 0; --i) {
    const auto& entry = headerStack[i];
    if (entry->getType() == HeaderEntry::IPV4) {
      auto* ipv4 = static_cast<const IPv4Header*>(entry.get());
      *ipv4Header = ipv4->getHeader();
      return;
    } else if (entry->getType() == HeaderEntry::IPV6) {
      auto* ipv6 = static_cast<const IPv6Header*>(entry.get());
      *ipv6Header = ipv6->getHeader();
      return;
    }
  }
}

uint16_t UDPHeader::calculateChecksum(
    const std::vector<uint8_t>& data,
    size_t start,
    size_t len) {
  if (len == 0) {
    len = data.size() - start;
  }

  uint32_t sum = 0;

  // Sum all 16-bit words in network byte order
  for (size_t i = start; i < start + len - 1; i += 2) {
    uint16_t word = (static_cast<uint16_t>(data[i]) << 8) +
        static_cast<uint16_t>(data[i + 1]);
    sum += word;
  }

  // Add odd byte if present (pad with zero)
  if (len % 2 == 1) {
    sum += static_cast<uint16_t>(data[start + len - 1]) << 8;
  }

  // Add carry bits
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  return static_cast<uint16_t>(~sum);
}

uint16_t UDPHeader::calculateUdpChecksum(
    const struct udphdr& udpHeader,
    const struct iphdr& ipHeader,
    const std::vector<uint8_t>& payload) {
  auto pseudoHeader =
      buildIPv4PseudoHeader(ipHeader, IPPROTO_UDP, ntohs(udpHeader.len));

  struct udphdr udpForChecksum = udpHeader;
  udpForChecksum.check = 0;

  return calculateTransportChecksum(
      std::move(pseudoHeader), &udpForChecksum, sizeof(struct udphdr), payload);
}

uint16_t UDPHeader::calculateUdpChecksumV6(
    const struct udphdr& udpHeader,
    const struct ip6_hdr& ip6Header,
    const std::vector<uint8_t>& payload) {
  auto pseudoHeader =
      buildIPv6PseudoHeader(ip6Header, IPPROTO_UDP, ntohs(udpHeader.len));

  struct udphdr udpForChecksum = udpHeader;
  udpForChecksum.check = 0;

  uint16_t checksum = calculateTransportChecksum(
      std::move(pseudoHeader), &udpForChecksum, sizeof(struct udphdr), payload);

  // For UDP over IPv6, if checksum is 0, it must be set to 0xFFFF
  // because 0 means no checksum was calculated
  if (checksum == 0) {
    checksum = UDP_IPV6_ZERO_CHECKSUM_REPLACEMENT;
  }

  return checksum;
}

std::vector<uint8_t> UDPHeader::buildIPv4PseudoHeader(
    const struct iphdr& ipHeader,
    uint8_t protocol,
    uint16_t length) {
  std::vector<uint8_t> pseudoHeader(IPV4_PSEUDO_HEADER_SIZE);

  // Source IP (4 bytes)
  std::memcpy(pseudoHeader.data(), &ipHeader.saddr, 4);
  // Destination IP (4 bytes)
  std::memcpy(pseudoHeader.data() + 4, &ipHeader.daddr, 4);
  // Zero (1 byte)
  pseudoHeader[8] = 0;
  // Protocol (1 byte)
  pseudoHeader[9] = protocol;
  // Length (2 bytes)
  uint16_t netLength = htons(length);
  std::memcpy(pseudoHeader.data() + 10, &netLength, 2);

  return pseudoHeader;
}

std::vector<uint8_t> UDPHeader::buildIPv6PseudoHeader(
    const struct ip6_hdr& ip6Header,
    uint8_t protocol,
    uint16_t length) {
  std::vector<uint8_t> pseudoHeader(IPV6_PSEUDO_HEADER_SIZE);

  // Source IP (16 bytes)
  const uint8_t* srcBytes =
      reinterpret_cast<const uint8_t*>(&ip6Header.ip6_src);
  std::memcpy(pseudoHeader.data(), srcBytes, 16);

  // Destination IP (16 bytes)
  const uint8_t* dstBytes =
      reinterpret_cast<const uint8_t*>(&ip6Header.ip6_dst);
  std::memcpy(pseudoHeader.data() + 16, dstBytes, 16);

  // Upper-Layer Packet Length (4 bytes)
  uint32_t netLength = htonl(length);
  std::memcpy(pseudoHeader.data() + 32, &netLength, 4);

  // Zero (3 bytes)
  pseudoHeader[36] = 0;
  pseudoHeader[37] = 0;
  pseudoHeader[38] = 0;

  // Next Header (1 byte)
  pseudoHeader[39] = protocol;

  return pseudoHeader;
}

uint16_t UDPHeader::calculateTransportChecksum(
    std::vector<uint8_t> pseudoHeader,
    const void* transportHeader,
    size_t transportHeaderSize,
    const std::vector<uint8_t>& payload) {
  std::vector<uint8_t> checksumData;
  checksumData.reserve(
      pseudoHeader.size() + transportHeaderSize + payload.size());

  // Add pseudo header
  checksumData.insert(
      checksumData.end(),
      std::make_move_iterator(pseudoHeader.begin()),
      std::make_move_iterator(pseudoHeader.end()));

  // Add transport header
  const uint8_t* headerBytes =
      reinterpret_cast<const uint8_t*>(transportHeader);
  checksumData.insert(
      checksumData.end(), headerBytes, headerBytes + transportHeaderSize);

  // Add payload
  checksumData.insert(checksumData.end(), payload.begin(), payload.end());

  return calculateChecksum(checksumData);
}

// TCPHeader implementation
TCPHeader::TCPHeader(
    uint16_t sport,
    uint16_t dport,
    uint32_t seq,
    uint32_t ackSeq,
    uint16_t window,
    uint8_t flags) {
  std::memset(&tcp_, 0, sizeof(tcp_));

  tcp_.source = htons(sport);
  tcp_.dest = htons(dport);
  tcp_.seq = htonl(seq);
  tcp_.ack_seq = htonl(ackSeq);
  tcp_.doff = TCP_MIN_HEADER_LENGTH; // 4*5=20 bytes TCP header length
  tcp_.fin = (flags & TH_FIN) ? 1 : 0;
  tcp_.syn = (flags & TH_SYN) ? 1 : 0;
  tcp_.rst = (flags & TH_RST) ? 1 : 0;
  tcp_.psh = (flags & TH_PUSH) ? 1 : 0;
  tcp_.ack = (flags & TH_ACK) ? 1 : 0;
  tcp_.urg = (flags & TH_URG) ? 1 : 0;
  tcp_.window = htons(window);
  tcp_.check = 0; // Will be calculated in serialize()
  tcp_.urg_ptr = 0;
}

void TCPHeader::serialize(
    size_t headerIndex,
    const std::vector<std::shared_ptr<HeaderEntry>>& headerStack,
    std::vector<uint8_t>& packet) {
  auto tcp = tcp_;

  // Find IP header for checksum calculation
  struct iphdr ipv4Header {};
  struct ip6_hdr ipv6Header {};
  findIPHeaderForChecksum(headerIndex, headerStack, &ipv4Header, &ipv6Header);

  // Calculate checksum using the already-built payload in packet
  if (ipv4Header.version == 4) {
    tcp.check = htons(calculateTcpChecksum(tcp, ipv4Header, packet));
  } else if ((ntohl(ipv6Header.ip6_flow) >> 28) == 6) {
    tcp.check = htons(calculateTcpChecksumV6(tcp, ipv6Header, packet));
  } else {
    LOG(WARNING) << "No IPv4/IPv6 header found for TCP checksum calculation, "
                 << "checksum will be 0";
  }

  const uint8_t* tcpBytes = reinterpret_cast<const uint8_t*>(&tcp);
  packet.insert(packet.begin(), tcpBytes, tcpBytes + sizeof(struct tcphdr));
}

std::string TCPHeader::generateScapyCommand() const {
  uint16_t sport = ntohs(tcp_.source);
  uint16_t dport = ntohs(tcp_.dest);
  std::string command =
      "TCP(sport=" + std::to_string(sport) + ", dport=" + std::to_string(dport);

  if (ntohl(tcp_.seq) != 0) {
    command += ", seq=" + std::to_string(ntohl(tcp_.seq));
  }
  if (ntohl(tcp_.ack_seq) != 0) {
    command += ", ack=" + std::to_string(ntohl(tcp_.ack_seq));
  }
  if (ntohs(tcp_.window) != DEFAULT_TCP_WINDOW) {
    command += ", window=" + std::to_string(ntohs(tcp_.window));
  }

  std::string flags;
  if (tcp_.fin)
    flags += "F";
  if (tcp_.syn)
    flags += "S";
  if (tcp_.rst)
    flags += "R";
  if (tcp_.psh)
    flags += "P";
  if (tcp_.ack)
    flags += "A";
  if (tcp_.urg)
    flags += "U";
  if (!flags.empty()) {
    command += ", flags='" + flags + "'";
  }

  command += ")";
  return command;
}

void TCPHeader::findIPHeaderForChecksum(
    size_t headerIndex,
    const std::vector<std::shared_ptr<HeaderEntry>>& headerStack,
    struct iphdr* ipv4Header,
    struct ip6_hdr* ipv6Header) {
  // Find the most recent IP header before the current header
  for (int i = static_cast<int>(headerIndex) - 1; i >= 0; --i) {
    const auto& entry = headerStack[i];
    if (entry->getType() == HeaderEntry::IPV4) {
      auto* ipv4 = static_cast<const IPv4Header*>(entry.get());
      *ipv4Header = ipv4->getHeader();
      return;
    } else if (entry->getType() == HeaderEntry::IPV6) {
      auto* ipv6 = static_cast<const IPv6Header*>(entry.get());
      *ipv6Header = ipv6->getHeader();
      return;
    }
  }
}

uint16_t TCPHeader::calculateChecksum(
    const std::vector<uint8_t>& data,
    size_t start,
    size_t len) {
  if (len == 0) {
    len = data.size() - start;
  }

  uint32_t sum = 0;

  // Sum all 16-bit words in network byte order
  for (size_t i = start; i < start + len - 1; i += 2) {
    uint16_t word = (static_cast<uint16_t>(data[i]) << 8) +
        static_cast<uint16_t>(data[i + 1]);
    sum += word;
  }

  // Add odd byte if present (pad with zero)
  if (len % 2 == 1) {
    sum += static_cast<uint16_t>(data[start + len - 1]) << 8;
  }

  // Add carry bits
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  return static_cast<uint16_t>(~sum);
}

uint16_t TCPHeader::calculateTcpChecksum(
    const struct tcphdr& tcpHeader,
    const struct iphdr& ipHeader,
    const std::vector<uint8_t>& payload) {
  uint16_t tcpLength = sizeof(struct tcphdr) + payload.size();
  auto pseudoHeader = buildIPv4PseudoHeader(ipHeader, IPPROTO_TCP, tcpLength);

  struct tcphdr tcpForChecksum = tcpHeader;
  tcpForChecksum.check = 0;

  return calculateTransportChecksum(
      std::move(pseudoHeader), &tcpForChecksum, sizeof(struct tcphdr), payload);
}

uint16_t TCPHeader::calculateTcpChecksumV6(
    const struct tcphdr& tcpHeader,
    const struct ip6_hdr& ip6Header,
    const std::vector<uint8_t>& payload) {
  uint16_t tcpLength = sizeof(struct tcphdr) + payload.size();
  auto pseudoHeader = buildIPv6PseudoHeader(ip6Header, IPPROTO_TCP, tcpLength);

  struct tcphdr tcpForChecksum = tcpHeader;
  tcpForChecksum.check = 0;

  return calculateTransportChecksum(
      std::move(pseudoHeader), &tcpForChecksum, sizeof(struct tcphdr), payload);
}

std::vector<uint8_t> TCPHeader::buildIPv4PseudoHeader(
    const struct iphdr& ipHeader,
    uint8_t protocol,
    uint16_t length) {
  std::vector<uint8_t> pseudoHeader(IPV4_PSEUDO_HEADER_SIZE);

  // Source IP (4 bytes)
  std::memcpy(pseudoHeader.data(), &ipHeader.saddr, 4);
  // Destination IP (4 bytes)
  std::memcpy(pseudoHeader.data() + 4, &ipHeader.daddr, 4);
  // Zero (1 byte)
  pseudoHeader[8] = 0;
  // Protocol (1 byte)
  pseudoHeader[9] = protocol;
  // Length (2 bytes)
  uint16_t netLength = htons(length);
  std::memcpy(pseudoHeader.data() + 10, &netLength, 2);

  return pseudoHeader;
}

std::vector<uint8_t> TCPHeader::buildIPv6PseudoHeader(
    const struct ip6_hdr& ip6Header,
    uint8_t protocol,
    uint16_t length) {
  std::vector<uint8_t> pseudoHeader(IPV6_PSEUDO_HEADER_SIZE);

  // Source IP (16 bytes)
  const uint8_t* srcBytes =
      reinterpret_cast<const uint8_t*>(&ip6Header.ip6_src);
  std::memcpy(pseudoHeader.data(), srcBytes, 16);

  // Destination IP (16 bytes)
  const uint8_t* dstBytes =
      reinterpret_cast<const uint8_t*>(&ip6Header.ip6_dst);
  std::memcpy(pseudoHeader.data() + 16, dstBytes, 16);

  // Upper-Layer Packet Length (4 bytes)
  uint32_t netLength = htonl(length);
  std::memcpy(pseudoHeader.data() + 32, &netLength, 4);

  // Zero (3 bytes)
  pseudoHeader[36] = 0;
  pseudoHeader[37] = 0;
  pseudoHeader[38] = 0;

  // Next Header (1 byte)
  pseudoHeader[39] = protocol;

  return pseudoHeader;
}

uint16_t TCPHeader::calculateTransportChecksum(
    std::vector<uint8_t> pseudoHeader,
    const void* transportHeader,
    size_t transportHeaderSize,
    const std::vector<uint8_t>& payload) {
  std::vector<uint8_t> checksumData;
  checksumData.reserve(
      pseudoHeader.size() + transportHeaderSize + payload.size());

  // Add pseudo header
  checksumData.insert(
      checksumData.end(),
      std::make_move_iterator(pseudoHeader.begin()),
      std::make_move_iterator(pseudoHeader.end()));

  // Add transport header
  const uint8_t* headerBytes =
      reinterpret_cast<const uint8_t*>(transportHeader);
  checksumData.insert(
      checksumData.end(), headerBytes, headerBytes + transportHeaderSize);

  // Add payload
  checksumData.insert(checksumData.end(), payload.begin(), payload.end());

  return calculateChecksum(checksumData);
}

// PayloadHeader implementation
PayloadHeader::PayloadHeader(const std::string& data) {
  payload_.assign(data.begin(), data.end());
}

PayloadHeader::PayloadHeader(const std::vector<uint8_t>& data) {
  payload_ = data;
}

void PayloadHeader::serialize(
    size_t headerIndex,
    const std::vector<std::shared_ptr<HeaderEntry>>& headerStack,
    std::vector<uint8_t>& packet) {
  packet.insert(packet.end(), payload_.begin(), payload_.end());
}

std::string PayloadHeader::generateScapyCommand() const {
  std::string payloadStr(payload_.begin(), payload_.end());
  return "'" + payloadStr + "'";
}

} // namespace testing
} // namespace katran
