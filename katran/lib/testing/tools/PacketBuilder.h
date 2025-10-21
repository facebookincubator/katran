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
#include <linux/icmp.h>
#include <linux/ip.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
}

namespace katran {
namespace testing {

constexpr uint32_t QUIC_V1_WIRE_FORMAT = 0xfaceb001;

class PacketBuilder;
/**
 * Base class for all packet headers
 */
class HeaderEntry {
 public:
  enum Type {
    ETH,
    IPV4,
    IPV6,
    UDP_HEADER,
    TCP_HEADER,
    ICMP_HEADER,
    ICMPV6_HEADER,
    ARP_HEADER,
    PAYLOAD
  };

  virtual ~HeaderEntry() = default;
  virtual Type getType() const = 0;
  virtual void serialize(
      size_t headerIndex,
      const std::vector<std::shared_ptr<HeaderEntry>>& headerStack,
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
      const std::vector<std::shared_ptr<HeaderEntry>>& headerStack,
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
      uint16_t flags = 0,
      uint8_t ihl = 5);
  Type getType() const override {
    return IPV4;
  }
  void serialize(
      size_t headerIndex,
      const std::vector<std::shared_ptr<HeaderEntry>>& headerStack,
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
      uint32_t flowLabel = 0,
      uint8_t nextHeader = 0);
  Type getType() const override {
    return IPV6;
  }
  void serialize(
      size_t headerIndex,
      const std::vector<std::shared_ptr<HeaderEntry>>& headerStack,
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
      const std::vector<std::shared_ptr<HeaderEntry>>& headerStack,
      std::vector<uint8_t>& packet) override;
  std::string generateScapyCommand() const override;

 private:
  struct udphdr udp_;
  void findIPHeaderForChecksum(
      size_t headerIndex,
      const std::vector<std::shared_ptr<HeaderEntry>>& headerStack,
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
 * TCP Option structure for custom TCP options
 */
struct TCPOption {
  uint8_t kind;
  std::vector<uint8_t>
      data; // For options with data (excludes kind and length bytes)

  explicit TCPOption(uint8_t k)
      : kind(k) {} // For single-byte options like NOP, EOL
  TCPOption(uint8_t k, const std::vector<uint8_t>& d) : kind(k), data(d) {}
  TCPOption(uint8_t k, const std::string& d)
      : kind(k), data(d.begin(), d.end()) {}
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
      uint8_t flags = (TH_ACK | TH_PUSH),
      const std::vector<TCPOption>& options = {});
  Type getType() const override {
    return TCP_HEADER;
  }
  void serialize(
      size_t headerIndex,
      const std::vector<std::shared_ptr<HeaderEntry>>& headerStack,
      std::vector<uint8_t>& packet) override;
  std::string generateScapyCommand() const override;

  // Add option to existing TCP header
  void addOption(const TCPOption& option);

 private:
  struct tcphdr tcp_;
  std::vector<TCPOption> options_;

  void findIPHeaderForChecksum(
      size_t headerIndex,
      const std::vector<std::shared_ptr<HeaderEntry>>& headerStack,
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
  std::vector<uint8_t> buildTCPOptions() const;
  size_t calculateTCPHeaderLength() const;
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
      const std::vector<std::shared_ptr<HeaderEntry>>& headerStack,
      std::vector<uint8_t>& packet) override;
  std::string generateScapyCommand() const override;

 private:
  std::vector<uint8_t> payload_;
};

/**
 * ICMPv4 header implementation
 */
class ICMPv4Header : public HeaderEntry {
 public:
  enum ICMPType {
    ECHO_REPLY = 0,
    DEST_UNREACH = 3,
    ECHO_REQUEST = 8,
  };

  enum ICMPCode {
    NO_CODE = 0,
    FRAG_NEEDED = 4,
  };

  ICMPv4Header(
      uint8_t type = ECHO_REQUEST,
      uint8_t code = NO_CODE,
      uint16_t id = 0,
      uint16_t sequence = 0);

  // For ICMP dest unreachable with embedded packet
  ICMPv4Header(
      uint8_t type,
      uint8_t code,
      uint16_t mtu,
      const std::vector<uint8_t>& embeddedPacket);

  // For ICMP dest unreachable with embedded packet from PacketBuilder
  ICMPv4Header(
      uint8_t type,
      uint8_t code,
      uint16_t mtu,
      const PacketBuilder& embeddedPacket);

  Type getType() const override {
    return ICMP_HEADER;
  }
  void serialize(
      size_t headerIndex,
      const std::vector<std::shared_ptr<HeaderEntry>>& headerStack,
      std::vector<uint8_t>& packet) override;
  std::string generateScapyCommand() const override;

 private:
  struct icmphdr icmp_ {};
  std::vector<uint8_t> embeddedData_;
  uint16_t calculateChecksum(const std::vector<uint8_t>& data);
  uint16_t
  calculateChecksum(const std::vector<uint8_t>& data, size_t start, size_t len);
};

/**
 * ICMPv6 header implementation
 */
class ICMPv6Header : public HeaderEntry {
 public:
  enum ICMPv6Type {
    ECHO_REQUEST = 128,
    ECHO_REPLY = 129,
    PACKET_TOO_BIG = 2,
  };

  ICMPv6Header(
      uint8_t type = ECHO_REQUEST,
      uint8_t code = 0,
      uint16_t id = 0,
      uint16_t sequence = 0);

  // For ICMPv6 packet too big with embedded packet from PacketBuilder
  ICMPv6Header(
      uint8_t type,
      uint8_t code,
      uint32_t mtu,
      const PacketBuilder& embeddedPacket);

  // For ICMPv6 packet too big with embedded packet
  ICMPv6Header(
      uint8_t type,
      uint8_t code,
      uint32_t mtu,
      const std::vector<uint8_t>& embeddedPacket);

  Type getType() const override {
    return ICMPV6_HEADER;
  }
  void serialize(
      size_t headerIndex,
      const std::vector<std::shared_ptr<HeaderEntry>>& headerStack,
      std::vector<uint8_t>& packet) override;
  std::string generateScapyCommand() const override;

 private:
  struct icmp6_hdr icmp6_ {};
  std::vector<uint8_t> embeddedData_;
  uint32_t mtu_{};
  uint16_t calculateChecksum(
      const std::vector<uint8_t>& data,
      const struct ip6_hdr& ip6Header,
      size_t start = 0,
      size_t len = 0);
};

/**
 * ARP header implementation
 */
class ARPHeader : public HeaderEntry {
 public:
  enum ARPOpcode { ARP_REQUEST = 1, ARP_REPLY = 2 };

  ARPHeader(
      uint16_t hardwareType = 1, // Ethernet = 1
      uint16_t protocolType = 0x0800, // IPv4 = 0x0800
      uint8_t hardwareLength = 6, // Ethernet = 6
      uint8_t protocolLength = 4, // IPv4 = 4
      uint16_t opcode = ARP_REQUEST,
      const std::string& senderHardwareAddr = "00:00:00:00:00:00",
      const std::string& senderProtocolAddr = "0.0.0.0",
      const std::string& targetHardwareAddr = "00:00:00:00:00:00",
      const std::string& targetProtocolAddr = "0.0.0.0");

  Type getType() const override {
    return ARP_HEADER;
  }
  void serialize(
      size_t headerIndex,
      const std::vector<std::shared_ptr<HeaderEntry>>& headerStack,
      std::vector<uint8_t>& packet) override;
  std::string generateScapyCommand() const override;

 private:
  struct arphdr {
    uint16_t ar_hrd; // Hardware type
    uint16_t ar_pro; // Protocol type
    uint8_t ar_hln; // Hardware address length
    uint8_t ar_pln; // Protocol address length
    uint16_t ar_op; // Operation code
    uint8_t ar_sha[6]; // Sender hardware address
    uint32_t ar_spa; // Sender protocol address
    uint8_t ar_tha[6]; // Target hardware address
    uint32_t ar_tpa; // Target protocol address
  } __attribute__((packed));

  struct arphdr arp_ {};
  std::vector<uint8_t> macStringToBytes(const std::string& macStr);
  uint32_t ipStringToBytes(const std::string& ipStr);
};

/**
 * QUIC header implementation
 */
class QUICHeader : public HeaderEntry {
 public:
  enum QUICType {
    CLIENT_INITIAL = 0x00,
    ZERO_RTT = 0x10,
    HANDSHAKE = 0x20,
    RETRY = 0x30,
    SHORT_HEADER = 0x40
  };

  enum ConnectionIdVersion { CID_V1 = 1, CID_V2 = 2 };

  QUICHeader(
      QUICType type = CLIENT_INITIAL,
      const std::vector<uint8_t>& destConnectionId = {},
      uint32_t version = 0x01b0cefa, // QUIC version in host byte order
      const std::vector<uint8_t>& srcConnectionId = {},
      uint64_t packetNumber = 0,
      const std::vector<uint8_t>& token = {},
      ConnectionIdVersion cidVersion = CID_V1,
      uint8_t packetNumberLength = 4);

  Type getType() const override {
    return PAYLOAD; // QUIC is treated as UDP payload
  }
  void serialize(
      size_t headerIndex,
      const std::vector<std::shared_ptr<HeaderEntry>>& headerStack,
      std::vector<uint8_t>& packet) override;
  std::string generateScapyCommand() const override;

  // Methods to append additional QUIC data
  void appendData(const std::vector<uint8_t>& data);
  void appendData(const std::string& data);

 private:
  QUICType type_;
  std::vector<uint8_t> destConnectionId_;
  std::vector<uint8_t> srcConnectionId_;
  uint32_t version_;
  uint64_t packetNumber_;
  uint8_t packetNumberLength_; // Length of packet number in bytes
  std::vector<uint8_t> token_; // Token for Initial packets
  ConnectionIdVersion cidVersion_; // Connection ID version (V1 or V2)
  std::vector<uint8_t> additionalData_; // Store additional QUIC data

  std::vector<uint8_t> encodeVariableLengthInteger(uint64_t value);
  std::vector<uint8_t> encodePacketNumber(
      uint64_t packetNumber,
      uint8_t length);
  uint8_t getConnectionIdLength(const std::vector<uint8_t>& connId);
};

/**
 *
 * Example usage:
 *   auto packet = PacketBuilder::newPacket()
 *       .Eth("0x1", "0x2")
 *       .IPv4("192.168.1.42", "10.200.1.5")
 *       .UDP(31337, 443)
 *       .QUICInitial()
 *           .destConnId({0x41, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00})
 *           .token({0x11})
 *           .data("quic data")
 *           .done()
 *       .build();
 */
class PacketBuilder;

class QUICBuilder {
 public:
  explicit QUICBuilder(QUICHeader::QUICType type, PacketBuilder& parentBuilder);

  QUICBuilder& destConnId(const std::vector<uint8_t>& connId);
  QUICBuilder& srcConnId(const std::vector<uint8_t>& connId);
  QUICBuilder& version(uint32_t version);
  QUICBuilder& token(const std::vector<uint8_t>& token);
  QUICBuilder& packetNumber(uint64_t pn, uint8_t lengthBytes = 4);
  QUICBuilder& cidVersion(QUICHeader::ConnectionIdVersion version);
  QUICBuilder& data(const std::string& payload);
  QUICBuilder& data(const std::vector<uint8_t>& payload);

  // Finalize and return to parent builder
  PacketBuilder& done();

 private:
  QUICHeader::QUICType type_;
  PacketBuilder& parentBuilder_;
  std::vector<uint8_t> destConnId_;
  std::vector<uint8_t> srcConnId_;
  uint32_t version_ = QUIC_V1_WIRE_FORMAT;
  std::vector<uint8_t> token_;
  uint64_t packetNumber_ = 0;
  uint8_t packetNumberLength_ = 0;
  QUICHeader::ConnectionIdVersion cidVersion_ = QUICHeader::CID_V1;
  std::string payload_;

  void validate() const;
  void buildAndAddToParent();
};

/**
 *
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
  static constexpr uint8_t STABLE_UDP_TYPE = 0x52;
  static constexpr auto STABLE_UDP_HEADER_SIZE = 8;

  // IPv4 fragmentation flags
  static constexpr uint16_t IP_FLAG_MF = 0x20; // More Fragments (bit 13)
  static constexpr uint16_t IP_FLAG_DF = 0x40; // Don't Fragment (bit 14)

  // IPv6 next header values
  static constexpr uint8_t IPV6_NH_FRAGMENT = 44; // IPv6 Fragment header

  struct PacketResult {
    std::string base64Packet;
    std::string scapyCommand;
    size_t packetSize;
    std::vector<uint8_t> binaryPacket;
  };

  // Default constructor
  PacketBuilder() = default;

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
      uint16_t flags = 0,
      uint8_t ihl = 5);

  PacketBuilder& IPv6(
      const std::string& src,
      const std::string& dst,
      uint8_t hopLimit = 64,
      uint8_t trafficClass = 0,
      uint32_t flowLabel = 0,
      uint8_t nextHeader = 0);

  PacketBuilder& UDP(uint16_t sport, uint16_t dport);

  PacketBuilder& TCP(
      uint16_t sport,
      uint16_t dport,
      uint32_t seq = 0,
      uint32_t ackSeq = 0,
      uint16_t window = 8192,
      uint8_t flags = (TH_ACK | TH_PUSH));

  PacketBuilder& TCP(
      uint16_t sport,
      uint16_t dport,
      uint32_t seq,
      uint32_t ackSeq,
      uint16_t window,
      uint8_t flags,
      const std::vector<TCPOption>& options);

  // Method chaining for TCP options
  PacketBuilder& withTPR(uint32_t tprId);
  PacketBuilder& withMSS(uint16_t mss);
  PacketBuilder& withWindowScale(uint8_t scale);
  PacketBuilder& withTimestamp(uint32_t tsval, uint32_t tsecr = 0);
  PacketBuilder& withSACKPermitted();
  PacketBuilder& withNOP(int count = 1);
  PacketBuilder& withCustomOption(
      uint8_t kind,
      const std::vector<uint8_t>& data = {});

  PacketBuilder& payload(const std::string& data);

  PacketBuilder& payload(const std::vector<uint8_t>& data);

  PacketBuilder& stableRoutingPayload(
      const std::vector<uint8_t>& connectionId,
      const std::string& payload);

  // ICMP methods
  PacketBuilder& ICMP(
      uint8_t type = ICMPv4Header::ECHO_REQUEST,
      uint8_t code = ICMPv4Header::NO_CODE,
      uint16_t id = 0,
      uint16_t sequence = 0);

  // ICMPv6 methods
  PacketBuilder& ICMPv6(
      uint8_t type = ICMPv6Header::ECHO_REQUEST,
      uint8_t code = 0,
      uint16_t id = 0,
      uint16_t sequence = 0);

  // ARP methods
  PacketBuilder& ARP(
      uint16_t opcode = ARPHeader::ARP_REQUEST,
      const std::string& senderHardwareAddr = "00:00:00:00:00:00",
      const std::string& senderProtocolAddr = "0.0.0.0",
      const std::string& targetHardwareAddr = "00:00:00:00:00:00",
      const std::string& targetProtocolAddr = "0.0.0.0");

  QUICBuilder QUICInitial();
  QUICBuilder QUICHandshake();
  QUICBuilder QUICRetry();
  QUICBuilder QUIC0RTT();
  QUICBuilder QUICShortHeader();

  PacketResult build() const;

  std::vector<uint8_t> buildAsBytes() const;

 private:
  friend class QUICBuilder;
  std::vector<std::shared_ptr<HeaderEntry>> headerStack_;

  std::vector<uint8_t> buildBinaryPacket();
  std::string generateScapyCommand();
  std::string bytesToBase64(const std::vector<uint8_t>& bytes) const;
  static bool isValidMacAddress(const std::string& mac);
  static bool isValidIPv4Address(const std::string& ip);
  static bool isValidIPv6Address(const std::string& ip);
  static bool isValidPort(uint16_t port);
};

} // namespace testing
} // namespace katran
