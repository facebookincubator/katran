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

#include "tools/xdpdump/XdpEventReader.h"

#include <bcc/libbpf.h>
#include <folly/String.h>
#include <folly/io/async/EventBase.h>
#include <unistd.h>

namespace xdpdump {

void XdpEventReader::handlePerfBufferEvent(
    int /* cpu */,
    const char* data,
    size_t /* size */) noexcept {
  auto info = eventLogger_->handlePerfEvent(data);
  if (queue_ != nullptr) {
    katran::PcapMsg pcap_msg(
        data + info.hdr_size, info.pkt_size, info.data_len);
    // best effort non blocking write. if writer thread is full we will lose
    // this packet
    auto res = queue_->write(std::move(pcap_msg));
    if (!res) {
      // queue is full and we wasnt able to write into it.
      ++queueFull_;
    }
  }
}

} // namespace xdpdump
