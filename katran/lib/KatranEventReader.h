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

#include <folly/MPMCQueue.h>
#include "katran/lib/PcapMsgMeta.h"
#include "katran/lib/PerfBufferEventReader.h"

namespace folly {
class EventBase;
}

namespace katran {
class KatranEventReader : public PerfBufferEventReader {
 public:
  explicit KatranEventReader(
      std::shared_ptr<folly::MPMCQueue<PcapMsgMeta>> queue)
      : queue_(queue) {}

  /**
   * @param int cpu
   * @param const char* data received from the XDP prog.
   * @param size_t size of the data chunk
   */
  void handlePerfBufferEvent(int cpu, const char* data, size_t size) noexcept
      override;

 private:
  /**
   * queue toward PcapWriter
   */
  std::shared_ptr<folly::MPMCQueue<PcapMsgMeta>> queue_;
};
} // namespace katran
