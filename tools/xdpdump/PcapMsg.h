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

#include <memory>

#include <folly/io/IOBuf.h>

namespace xdpdump {
/**
 * Helper class-wrapper to send packets, received from forwarding plane,
 * thru MPMCQueue
 */
class PcapMsg {
public:
  /**
   * @param const char* pckt pointer to the raw packet
   * @param uint32_t origLen original length of the packet on wire
   * @param uint32_t capturedLen length of the captured segment
   */
  PcapMsg(const char *pckt, uint32_t origLen, uint32_t capturedLen);
  PcapMsg(PcapMsg &&msg) noexcept;
  PcapMsg(const PcapMsg &msg) = delete;
  PcapMsg &operator=(PcapMsg &&msg) noexcept;
  PcapMsg &operator=(const PcapMsg &msg) = delete;
  uint32_t getOrigLen() { return origLen_; };
  uint32_t getOrigLen() const { return origLen_; };
  uint32_t getCapturedLen() { return capturedLen_; };
  uint32_t getCapturedLen() const { return capturedLen_; };
  const uint8_t *getRawBuffer() { return pckt_->data(); };
  const uint8_t *getRawBuffer() const { return pckt_->data(); };
  /**
   * PcapMsg with a pointer to the packet equals to nullptr treated as a
   * marker message to turn off pcap file writer
   */

  bool emptyMsg() { return (pckt_ == nullptr); }

  uint32_t trim(uint32_t snaplen) {
    return capturedLen_ = std::min(capturedLen_, snaplen);
    ;
  }

private:
  /**
   * IOBuf which contains chunk of the captured packet
   */
  std::unique_ptr<folly::IOBuf> pckt_;
  /**
   * length of original packet
   */
  uint32_t origLen_{0};
  /**
   * length of the captured chunk. as we could e.g. capture only first N bytes
   * of the packet
   */
  uint32_t capturedLen_{0};
};

} // namespace xdpdump
