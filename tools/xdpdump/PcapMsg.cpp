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

#include "PcapMsg.h"

namespace xdpdump {

PcapMsg::PcapMsg(const char *pckt, uint32_t origLen, uint32_t capturedLen)
    : origLen_(origLen), capturedLen_(capturedLen) {
  if (pckt != nullptr) {
    pckt_ = folly::IOBuf::copyBuffer(pckt, capturedLen);
  }
}

PcapMsg &PcapMsg::operator=(PcapMsg &&msg) noexcept {
  pckt_ = std::move(msg.pckt_);
  origLen_ = msg.origLen_;
  capturedLen_ = msg.capturedLen_;
  return *this;
}

PcapMsg::PcapMsg(PcapMsg &&msg) noexcept
    : pckt_(std::move(msg.pckt_)), origLen_(msg.origLen_),
      capturedLen_(msg.capturedLen_) {}
} // namespace xdpdump
