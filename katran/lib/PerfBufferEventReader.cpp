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

#include "katran/lib/PerfBufferEventReader.h"

namespace {

// Callback for handling event sample, supplied to perf_buffer_opts
static void handleEvent(void* ctx, int cpu, void* rawData, __u32 dataSize) {
  auto perfBufferReader =
      reinterpret_cast<::katran::PerfBufferEventReader*>(ctx);
  perfBufferReader->handlePerfBufferEvent(
      cpu, reinterpret_cast<const char*>(rawData), dataSize);
}

// Callback for handling event loss, supplied to perf_buffer_opts
static void handleLost(void* ctx, int cpu, __u64 lostCount) {
  LOG(ERROR) << "cpu: " << cpu << " lost " << lostCount << " events!";
  auto perfBufferReader =
      reinterpret_cast<::katran::PerfBufferEventReader*>(ctx);
  perfBufferReader->handlePerfBufferLoss(cpu, lostCount);
}

bool isPowerOf2(uint64_t x) {
  return (x & (x - 1)) == 0;
}

} // namespace

namespace katran {

PerfBufferEventReader::~PerfBufferEventReader() {
  perf_buffer__free(pb_);
}

bool PerfBufferEventReader::open(
    int bpfPerfMap,
    folly::EventBase* evb,
    size_t pageCount) {
  CHECK(evb != nullptr) << "Null event base";

  // At least two pages for sanity, same value used as default by
  // PerfEventReader
  if (pageCount == 0 || !isPowerOf2(pageCount)) {
    LOG(ERROR) << "pageCount must be greater than 0 and power of two";
    return false;
  }

  struct perf_buffer_opts pbOpts = {
      .sample_cb = handleEvent,
      .lost_cb = handleLost,
      .ctx = this,
  };

  pb_ = perf_buffer__new(bpfPerfMap, pageCount, &pbOpts);
  auto maybeError = libbpf_get_error(pb_);
  if (maybeError != 0) {
    LOG(ERROR) << "perf_buffer__new() failed: " << maybeError;
    return false;
  }

  size_t bufCnt = perf_buffer__buffer_cnt(pb_);
  if (bufCnt == 0) {
    LOG(ERROR) << "cpu buffer count is 0";
    return false;
  }
  for (size_t i = 0; i < bufCnt; i++) {
    int bufFd = perf_buffer__buffer_fd(pb_, i);
    cpuBufferHandlers_.push_back(
        std::make_unique<PerfBufferEventReader::CpuBufferHandler>(
            evb, pb_, bufFd, i));
  }

  return true;
}

PerfBufferEventReader::CpuBufferHandler::CpuBufferHandler(
    folly::EventBase* evb,
    struct perf_buffer* pb,
    int fd,
    size_t idx)
    : pb_(pb), bufFd_(fd), bufIdx_(idx) {
  initHandler(evb, folly::NetworkSocket::fromFd(bufFd_));
  if (!registerHandler(READ | PERSIST)) {
    LOG(ERROR) << "Error registering for reading events";
  }
}

void PerfBufferEventReader::CpuBufferHandler::handlerReady(
    uint16_t /* events */) noexcept {
  int res = perf_buffer__consume_buffer(pb_, bufIdx_);
  if (res != 0) {
    LOG(ERROR) << "Error while polling perf event: " << res;
  }
}

} // namespace katran
