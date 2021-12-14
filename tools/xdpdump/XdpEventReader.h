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
#include <string>

#include <folly/MPMCQueue.h>
#include <folly/io/async/EventHandler.h>
#include "katran/lib/PerfBufferEventReader.h"

#include "katran/lib/PcapMsg.h"
#include "katran/lib/PcapWriter.h"
#include "tools/xdpdump/XdpDumpStructs.h"
#include "tools/xdpdump/XdpEventLogger.h"

namespace xdpdump {

class XdpEventLogger;

/**
 * Perf event reader implementation. we are reading data
 * from XDP, print it to the cli, and, if configured
 * sending it to pcapWriter thru MPMCQueue.
 */
class XdpEventReader : public katran::PerfBufferEventReader {
 public:
  /**
   * @param shared_ptr<MPMCQueue<PcapMsg>> queue to pcapWriter
   */
  explicit XdpEventReader(
      std::shared_ptr<folly::MPMCQueue<katran::PcapMsg>> queue,
      std::shared_ptr<XdpEventLogger> eventLogger)
      : queue_(queue), eventLogger_(eventLogger) {}

  /**
   * @param int cpu
   * @param const char* data received from the XDP prog.
   * @param size_t size of the data chunk
   */
  void handlePerfBufferEvent(int cpu, const char* data, size_t size) noexcept
      override;

 private:
  /**
   * queue where we write data, which will be read by PcapWriter.
   * write is non-blocking. so if queue is full - we will drop the packet
   */
  std::shared_ptr<folly::MPMCQueue<katran::PcapMsg>> queue_;

  /**
   * counter of how many times non blocking write failed.
   */
  uint64_t queueFull_;

  std::shared_ptr<XdpEventLogger> eventLogger_;
};

} // namespace xdpdump
