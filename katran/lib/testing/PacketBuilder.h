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

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

extern "C" {
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
}

namespace katran {
namespace testing {

/**
 * Base class for all packet headers
 */
class HeaderEntry {
 public:
  enum Type { ETH, IPV4, IPV6, UDP_HEADER, TCP_HEADER, PAYLOAD };

  virtual ~HeaderEntry() = default;
  virtual Type getType() const = 0;
  virtual void serialize(
      size_t headerIndex,
      const std::vector<std::unique_ptr<HeaderEntry>>& headerStack,
      std::vector<uint8_t>& packet) = 0;
  virtual std::string generateScapyCommand() const = 0;
  virtual void updateForNextHeader(Type nextHeaderType) {}
};

/**
 * Ethernet header implementation
 */
class EthernetHeader : public HeaderEntry {
 public:
  EthernetHeader(const std::string& src, const std::string& dst);
  Type getType() const override {
    return ETH;
  }
  void serialize(
      size_t headerIndex,
      const std::vector<std::unique_ptr<HeaderEntry>>& headerStack,
      std::vector<uint8_t>& packet) override;
  std::string generateScapyCommand() const override;
  void updateForNextHeader(Type nextHeaderType) override;

 private:
  struct ethhdr eth_;
  std::vector<uint8_t> macStringToBytes(const std::string& macStr);
};

/**
 * IPv4 header implementation
 */
class IPv4Header : public HeaderEntry {
 public:
  IPv4Header(
      const std::string& src,
      const std::string& dst,
      uint8_t ttl = 64,
      uint8_t tos = 0,
      uint16_t id = 1,
      uint16_t flags = 0);
  Type getType() const override {
    return IPV4;
  }
  void serialize(
      size_t headerIndex,
      const std::vector<std::unique_ptr<HeaderEntry>>& headerStack,
      std::vector<uint8_t>& packet) override;
  std::string generateScapyCommand() const override;
  void updateForNextHeader(Type nextHeaderType) override;
  const struct iphdr& getHeader() const {
    return ip_;
  }

 private:
  struct iphdr ip_;
  uint16_t calculateChecksum(
      const std::vector<uint8_t>& data,
      size_t start = 0,
      size_t len = 0);
};

/**
 * IPv6 header implementation
 */
class IPv6Header : public HeaderEntry {
 public:
  IPv6Header(
      const std::string& src,
      const std::string& dst,
      uint8_t hopLimit = 64,
      uint8_t trafficClass = 0,
      uint32_t flowLabel = 0);
  Type getType() const override {
    return IPV6;
  }
  void serialize(
      size_t headerIndex,
      const std::vector<std::unique_ptr<HeaderEntry>>& headerStack,
      std::vector<uint8_t>& packet) override;
  std::string generateScapyCommand() const override;
  void updateForNextHeader(Type nextHeaderType) override;
  const struct ip6_hdr& getHeader() const {
    return ip6_;
  }

 private:
  struct ip6_hdr ip6_;
};

/**
 * UDP header implementation
 */
class UDPHeader : public HeaderEntry {
 public:
  UDPHeader(uint16_t sport, uint16_t dport);
  Type getType() const override {
    return UDP_HEADER;
  }
  void serialize(
      size_t headerIndex,
      const std::vector<std::unique_ptr<HeaderEntry>>& headerStack,
      std::vector<uint8_t>& packet) override;
  std::string generateScapyCommand() const override;

 private:
  struct udphdr udp_;
  void findIPHeaderForChecksum(
      size_t headerIndex,
      const std::vector<std::unique_ptr<HeaderEntry>>& headerStack,
      struct iphdr* ipv4Header,
      struct ip6_hdr* ipv6Header);
  uint16_t calculateChecksum(
      const std::vector<uint8_t>& data,
      size_t start = 0,
      size_t len = 0);
  std::vector<uint8_t> buildIPv4PseudoHeader(
      const struct iphdr& ipHeader,
      uint8_t protocol,
      uint16_t length);
  std::vector<uint8_t> buildIPv6PseudoHeader(
      const struct ip6_hdr& ip6Header,
      uint8_t protocol,
      uint16_t length);
  uint16_t calculateTransportChecksum(
      std::vector<uint8_t> pseudoHeader,
      const void* transportHeader,
      size_t transportHeaderSize,
      const std::vector<uint8_t>& payload);
  uint16_t calculateUdpChecksum(
      const struct udphdr& udpHeader,
      const struct iphdr& ipHeader,
      const std::vector<uint8_t>& payload);
  uint16_t calculateUdpChecksumV6(
      const struct udphdr& udpHeader,
      const struct ip6_hdr& ip6Header,
      const std::vector<uint8_t>& payload);
};

/**
 * TCP header implementation
 */
class TCPHeader : public HeaderEntry {
 public:
  TCPHeader(
      uint16_t sport,
      uint16_t dport,
      uint32_t seq = 0,
      uint32_t ackSeq = 0,
      uint16_t window = 8192,
      uint8_t flags = (TH_ACK | TH_PUSH));
  Type getType() const override {
    return TCP_HEADER;
  }
  void serialize(
      size_t headerIndex,
      const std::vector<std::unique_ptr<HeaderEntry>>& headerStack,
      std::vector<uint8_t>& packet) override;
  std::string generateScapyCommand() const override;

 private:
  struct tcphdr tcp_;
  void findIPHeaderForChecksum(
      size_t headerIndex,
      const std::vector<std::unique_ptr<HeaderEntry>>& headerStack,
      struct iphdr* ipv4Header,
      struct ip6_hdr* ipv6Header);
  uint16_t calculateChecksum(
      const std::vector<uint8_t>& data,
      size_t start = 0,
      size_t len = 0);
  std::vector<uint8_t> buildIPv4PseudoHeader(
      const struct iphdr& ipHeader,
      uint8_t protocol,
      uint16_t length);
  std::vector<uint8_t> buildIPv6PseudoHeader(
      const struct ip6_hdr& ip6Header,
      uint8_t protocol,
      uint16_t length);
  uint16_t calculateTransportChecksum(
      std::vector<uint8_t> pseudoHeader,
      const void* transportHeader,
      size_t transportHeaderSize,
      const std::vector<uint8_t>& payload);
  uint16_t calculateTcpChecksum(
      const struct tcphdr& tcpHeader,
      const struct iphdr& ipHeader,
      const std::vector<uint8_t>& payload);
  uint16_t calculateTcpChecksumV6(
      const struct tcphdr& tcpHeader,
      const struct ip6_hdr& ip6Header,
      const std::vector<uint8_t>& payload);
};

/**
 * Payload implementation
 */
class PayloadHeader : public HeaderEntry {
 public:
  explicit PayloadHeader(const std::string& data);
  explicit PayloadHeader(const std::vector<uint8_t>& data);
  Type getType() const override {
    return PAYLOAD;
  }
  void serialize(
      size_t headerIndex,
      const std::vector<std::unique_ptr<HeaderEntry>>& headerStack,
      std::vector<uint8_t>& packet) override;
  std::string generateScapyCommand() const override;

 private:
  std::vector<uint8_t> payload_;
};

/**
 * Usage:
 *   auto packet = PacketBuilder::newPacket()
 *       .Eth(src="01:00:00:00:00:00", dst="02:00:00:00:00:00")
 *       .IPv4(src="192.168.1.1", dst="10.200.1.1")
 *       .UDP(sport=31337, dport=80)
 *       .payload("katran test pkt")
 *       .build();
 *
 * For GUE encapsulation, use:
 *   auto packet = PacketBuilder::newPacket()
 *       .Eth("01:00:00:00:00:00", "02:00:00:00:00:00")
 *       .IPv6("100::64", "fc00:1404::1")     // outer IPv6
 *       .UDP(31337, 9886)                    // outer UDP (GUE)
 *       .IPv4("192.168.1.1", "10.200.1.1")  // inner IPv4
 *       .UDP(31337, 80)                      // inner UDP
 *       .payload("katran test pkt")
 *       .build();
 */
class PacketBuilder {
 public:
  struct PacketResult {
    std::string base64Packet;
    std::string scapyCommand;
    size_t packetSize;
  };

  static PacketBuilder newPacket();

  PacketBuilder& Eth(
      const std::string& src = "0x1",
      const std::string& dst = "0x2");

  PacketBuilder& IPv4(
      const std::string& src,
      const std::string& dst,
      uint8_t ttl = 64,
      uint8_t tos = 0,
      uint16_t id = 1,
      uint16_t flags = 0);

  PacketBuilder& IPv6(
      const std::string& src,
      const std::string& dst,
      uint8_t hopLimit = 64,
      uint8_t trafficClass = 0,
      uint32_t flowLabel = 0);

  PacketBuilder& UDP(uint16_t sport, uint16_t dport);

  PacketBuilder& TCP(
      uint16_t sport,
      uint16_t dport,
      uint32_t seq = 0,
      uint32_t ackSeq = 0,
      uint16_t window = 8192,
      uint8_t flags = (TH_ACK | TH_PUSH));

  PacketBuilder& payload(const std::string& data);

  PacketBuilder& payload(const std::vector<uint8_t>& data);

  PacketResult build();

 private:
  std::vector<std::unique_ptr<HeaderEntry>> headerStack_;

  std::vector<uint8_t> buildBinaryPacket();
  std::string generateScapyCommand();
  std::string bytesToBase64(const std::vector<uint8_t>& bytes);
  static bool isValidMacAddress(const std::string& mac);
  static bool isValidIPv4Address(const std::string& ip);
  static bool isValidIPv6Address(const std::string& ip);
  static bool isValidPort(uint16_t port);
};

} // namespace testing
} // namespace katran
