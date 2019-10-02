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
#include <thread>
#include <vector>
#include <folly/io/IOBuf.h>
#include <folly/MPMCQueue.h>

#include "katran/lib/KatranLbStructs.h"
#include "katran/lib/PcapMsgMeta.h"
#include "katran/lib/PcapWriter.h"

namespace folly {
class ScopedEventBaseThread;
}

namespace katran {



class KatranEventReader;
class PcapWriter;
/**
 * helper class which runs all introspection related routines
 */
class KatranMonitor {
 public:
  KatranMonitor() = delete;

  explicit KatranMonitor(const KatranMonitorConfig& config);

  ~KatranMonitor();

  void stopMonitor();

  void restartMonitor(uint32_t limit);

  PcapWriterStats getWriterStats();

  std::unique_ptr<folly::IOBuf> getEventBuffer(int event);

 private:
  /**
   * main config
   */
  KatranMonitorConfig config_;

  /**
   * event readers for introspection
   */
  std::vector<std::unique_ptr<KatranEventReader>> readers_;

  std::shared_ptr<PcapWriter> writer_;

  /**
   * queue toward writer
   */
  std::shared_ptr<folly::MPMCQueue<PcapMsgMeta>> queue_;
  /**
   * event base thread to run readers.
   */
  std::unique_ptr<folly::ScopedEventBaseThread> scopedEvb_;

  /**
   * thread which runs pcap writer
   */
  std::thread writerThread_;

  /**
   * vector of iobufs where we store packets if IOBUF storage
   * is being used
   */
  std::vector<std::unique_ptr<folly::IOBuf>> buffers_;
};

} // namespace katran
