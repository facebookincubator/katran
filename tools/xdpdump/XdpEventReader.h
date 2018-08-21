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

extern "C" {
#include <linux/perf_event.h>
}

#include "PcapMsg.h"
#include "XdpDumpStructs.h"
#include "XdpEventLogger.h"

namespace xdpdump {

class PcapWriter;
class XdpEventLogger;

/**
 * Perf event reader implementation. we are reading data
 * from XDP, print it to the cli, and, if configured
 * sending it to pcapWriter thru MPMCQueue.
 */
class XdpEventReader : public folly::EventHandler {
public:
  /**
   * @param shared_ptr<MPMCQueue<PcapMsg>> queue to pcapWriter
   * @param XdpEventReaderMode mode of the event reader.
   * @param int pages number of pages for mmaped memory region
   * @param int cpu number where to attach this instance of xdpeventreader
   */
  XdpEventReader(std::shared_ptr<folly::MPMCQueue<PcapMsg>> queue,
                 std::shared_ptr<XdpEventLogger> eventLogger, int pages,
                 int cpu);
  ~XdpEventReader() override;

  /**
   * @param int eventMapFd descriptor of perf event map
   * @param EventBase* evb event base to run this reader in
   * @param int wakeUpNumEvents sampling rate: 1 out of wakeUpNumEvents
   * @return true on success
   *
   * helper function to start/open perf event reader
   */
  bool open(int eventMapFd, folly::EventBase *evb, int wakeUpNumEvents);

  /**
   * @param uint16_t events bitmask of events which have been fired
   *
   * function, which is going to be run when event happened
   */
  void handlerReady(uint16_t events) noexcept override;

private:
  /**
   * @param const char* data received from the XDP prog.
   * @param size_t size of the data chunk
   */
  void handlePerfEvent(const char *data, size_t size) noexcept;

  /**
   * queue where we write data, which will be read by PcapWriter.
   * write is non-blocking. so if queue is full - we will drop the packet
   */
  std::shared_ptr<folly::MPMCQueue<PcapMsg>> queue_;

  /**
   * counter of how many times non blocking write failed.
   */
  uint64_t queueFull_;

  std::shared_ptr<XdpEventLogger> eventLogger_;

  /**
   * ptr to mapped memory region
   */
  struct perf_event_mmap_page *header_ = nullptr;

  /**
   * buffer where packets are going to be stored
   */
  std::string buffer_;

  /**
   * size of mmaped memory region. in pages
   */
  int pages_;

  /**
   * cpu, to which this event reader is attached
   */
  int cpu_;

  /**
   * size of the page on current architecture
   */
  int pageSize_;
};

} // namespace xdpdump
