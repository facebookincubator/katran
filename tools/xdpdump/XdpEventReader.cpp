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

#include "XdpEventReader.h"

#include <folly/io/async/EventBase.h>
#include <unistd.h>

#include "katran/lib/BpfAdapter.h"

#include "PcapWriter.h"

namespace xdpdump {

XdpEventReader::XdpEventReader(std::shared_ptr<folly::MPMCQueue<PcapMsg>> queue,
                               std::shared_ptr<XdpEventLogger> eventLogger,
                               int pages, int cpu)
    : queue_(queue), eventLogger_(eventLogger), pages_(pages), cpu_(cpu) {
  pageSize_ = ::getpagesize();
}

XdpEventReader::~XdpEventReader() {
  katran::BpfAdapter::perfEventUnmmap(&header_, pages_);
}

bool XdpEventReader::open(int eventMapFd, folly::EventBase *evb,
                          int wakeUpNumEvents) {
  int fd;
  if (!katran::BpfAdapter::openPerfEvent(cpu_, eventMapFd, wakeUpNumEvents,
                                         pages_, &header_, fd)) {
    LOG(ERROR) << "can't open perf event for map with fd: " << eventMapFd;
    return false;
  }
  initHandler(evb, fd);
  if (!registerHandler(READ | PERSIST)) {
    LOG(ERROR) << "can't register XdpEventReader for read event";
    return false;
  }
  return true;
}

void XdpEventReader::handlerReady(uint16_t /* events */) noexcept {
  katran::BpfAdapter::handlePerfEvent(
      [this](const char *data, size_t size) { handlePerfEvent(data, size); },
      header_, buffer_, pageSize_, pages_, cpu_);
}

void XdpEventReader::handlePerfEvent(const char *data,
                                     size_t /* unused */) noexcept {
  auto info = eventLogger_->handlePerfEvent(data);
  if (queue_ != nullptr) {
    PcapMsg pcap_msg(data + info.hdr_size, info.pkt_size, info.data_len);
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
