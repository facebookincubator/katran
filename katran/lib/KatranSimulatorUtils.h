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

#include <folly/IPAddress.h>
#include <folly/io/IOBuf.h>
#include <memory>
#include <string>

namespace katran {

/**
 * struct that contains all the fields that uniquely identifies a flow
 */
struct KatranFlow {
  // source ip address of the packet
  std::string src;
  // destination ip address of the packet
  std::string dst;
  uint16_t srcPort;
  uint16_t dstPort;
  // protocol number (e.g. 6 for TCP, 17 for UDP)
  uint8_t proto;
};

class KatranSimulatorUtils {
 public:
  /**
   * Create an IPv4 packet with the specified parameters
   */
  static void createV4Packet(
      const folly::IPAddress& src,
      const folly::IPAddress& dst,
      std::unique_ptr<folly::IOBuf>& buf,
      uint8_t proto,
      uint16_t size,
      uint8_t ttl);

  /**
   * Create an IPv6 packet with the specified parameters
   */
  static void createV6Packet(
      const folly::IPAddress& src,
      const folly::IPAddress& dst,
      std::unique_ptr<folly::IOBuf>& buf,
      uint8_t proto,
      uint16_t size,
      uint8_t ttl);

  /**
   * Create a packet from a KatranFlow specification
   */
  static std::unique_ptr<folly::IOBuf> createPacketFromFlow(
      const KatranFlow& flow,
      uint16_t packetSize,
      uint8_t ttl = 64);

  /**
   * Create TCP header in the packet buffer
   */
  static void createTcpHeader(
      std::unique_ptr<folly::IOBuf>& buf,
      uint16_t srcPort,
      uint16_t dstPort,
      uint16_t offset);

  /**
   * Create UDP header in the packet buffer
   */
  static void createUdpHeader(
      std::unique_ptr<folly::IOBuf>& buf,
      uint16_t srcPort,
      uint16_t dstPort,
      uint16_t offset,
      uint16_t size);

  /**
   * Get the destination IP address from a packet
   */
  static std::string getPcktDst(std::unique_ptr<folly::IOBuf>& pckt);

  /**
   * Convert IPv4 address to string
   */
  static const std::string toV4String(uint32_t addr);

  /**
   * Convert IPv6 address to string
   */
  static const std::string toV6String(uint8_t const* v6);
};

} // namespace katran
