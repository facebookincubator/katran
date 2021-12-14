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
#include <bpf/libbpf.h>
#include <folly/io/async/EventHandler.h>

namespace katran {

/**
 * PerfBufferEventReader uses the new perf_buffer API available in libbpf. A
 * single reader is capable of reading events from all cpus. The cpu parameter
 * in handlePerfBufferEvent() can be used to de-multiplex the events by cpu.
 */
class PerfBufferEventReader {
 public:
  PerfBufferEventReader() = default;
  virtual ~PerfBufferEventReader();

  /**
   * Open a bpf perf map and register a handler to monitor all perf events in
   * all cpus
   * @param bpfPerfMap the fd of the bpf map, must of type
   * BPF_MAP_TYPE_PERF_ARRAY
   * @param evb event base to run this reader in
   * @param pageCount number of pages used for each cpu perf map, must be a
   * power of 2
   */
  bool open(int bpfPerfMap, folly::EventBase* evb, size_t pageCount);

  /**
   * Callback when an event is ready to consume
   * @param int cpu cpu index
   * @param const char* data raw data
   * @param size_t size data size in bytes
   */
  virtual void
  handlePerfBufferEvent(int cpu, const char* data, size_t size) noexcept = 0;

  /**
   * Callback when an event is determined lost
   * @param cpu cpu index
   * @param lostCount number of events lost
   */
  virtual void handlePerfBufferLoss(
      int /* cpu */,
      uint64_t /* lossCount */) noexcept {}

 private:
  /**
   * The internal per-cpu event handler
   */
  class CpuBufferHandler : public folly::EventHandler {
   public:
    /**
     * Ctor for CpuBufferHandler
     * @param evb EventBase
     * @param pb Pointer to perf_buffer struct, used to make perf_buffer API
     * calls
     * @param fd The buffer fd for a cpu
     * @param idx The buffer fd's index inside struct perf_buffer
     */
    CpuBufferHandler(
        folly::EventBase* evb,
        struct perf_buffer* pb,
        int fd,
        size_t idx);

    /**
     * EventHandler callback, will invoke perf_buffer__consume_buffer(), which
     * in turn calls PerfBufferEventReader::handlePerfBufferEvent()
     */
    void handlerReady(uint16_t events) noexcept override;

   private:
    /**
     * See ctor for the meaning and usages of these fields
     */
    struct perf_buffer* pb_{nullptr};
    int bufFd_;
    size_t bufIdx_;
  };

  /**
   * Pointer to perf_buffer struct
   */
  struct perf_buffer* pb_{nullptr};

  /**
   * Owned intsnaces of perf-cpu perf-buffer handler
   */
  std::vector<std::unique_ptr<CpuBufferHandler>> cpuBufferHandlers_;
};

} // namespace katran
