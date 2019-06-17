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
#include "katran/lib/KatranEventReader.h"

#include <folly/io/async/EventBase.h>
#include <unistd.h>

#include "katran/lib/BalancerStructs.h"
#include "katran/lib/BpfAdapter.h"

namespace katran {

KatranEventReader::KatranEventReader(
    int pages,
    int cpu,
    std::shared_ptr<folly::MPMCQueue<PcapMsgMeta>> queue)
    : pages_(pages), cpu_(cpu), queue_(queue) {
  pageSize_ = ::getpagesize();
}

KatranEventReader::~KatranEventReader() {
  katran::BpfAdapter::perfEventUnmmap(&header_, pages_);
}

bool KatranEventReader::open(
    int eventMapFd,
    folly::EventBase* evb,
    int wakeUpNumEvents) {
  int fd;
  if (!katran::BpfAdapter::openPerfEvent(
          cpu_, eventMapFd, wakeUpNumEvents, pages_, &header_, fd)) {
    LOG(ERROR) << "can't open perf event for map with fd: " << eventMapFd;
    return false;
  }
  initHandler(evb, folly::NetworkSocket::fromFd(fd));
  if (!registerHandler(READ | PERSIST)) {
    LOG(ERROR) << "can't register KatranEventReader for read event";
    return false;
  }
  return true;
}

void KatranEventReader::handlerReady(uint16_t /* events */) noexcept {
  katran::BpfAdapter::handlePerfEvent(
      [this](const char* data, size_t size) { handlePerfEvent(data, size); },
      header_,
      buffer_,
      pageSize_,
      pages_,
      cpu_);
}

void KatranEventReader::handlePerfEvent(
    const char* data,
    size_t size) noexcept {
  if (size < sizeof(struct event_metadata)) {
    return;
  }
  auto mdata = (struct event_metadata*)data;
  PcapMsg pcap_msg(
      data + sizeof(struct event_metadata), mdata->pkt_size, mdata->data_len);
  PcapMsgMeta pcap_msg_meta(std::move(pcap_msg), mdata->event);
  auto res = queue_->write(std::move(pcap_msg_meta));
  if (!res) {
    LOG(ERROR) << "writer queue is full";
  }
}

} // namespace katran
