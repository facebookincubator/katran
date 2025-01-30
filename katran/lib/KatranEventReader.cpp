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

#include "katran/lib/BalancerStructs.h"

namespace katran {

void KatranEventReader::handlePerfBufferEvent(
    int /* cpu */,
    const char* data,
    size_t size) noexcept {
  if (size < sizeof(struct event_metadata)) {
    LOG(ERROR) << "size " << size
               << " is less than sizeof(struct event_metadata) "
               << sizeof(struct event_metadata) << ", skipping";
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
  LOG(INFO) << __func__
            << "write perf event to queue, queue stats: " << queue_->size()
            << "/" << queue_->capacity();
}

} // namespace katran
