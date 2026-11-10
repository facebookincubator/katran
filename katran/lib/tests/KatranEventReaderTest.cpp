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
#include "katran/lib/MonitoringStructs.h"
#include "katran/lib/PcapMsgMeta.h"
#include "katran/lib/PerfBufferSizing.h"

#include <folly/MPMCQueue.h>
#include <gtest/gtest.h>
#include <cstring>
#include <limits>
#include <memory>
#include <vector>

namespace katran {

namespace {

auto makeQueue(size_t capacity = 16) {
  return std::make_shared<folly::MPMCQueue<PcapMsgMeta>>(capacity);
}

// Build a buffer with an event_metadata header followed by `data_len` bytes of
// payload (all initialized to 'x').
std::vector<char>
makeBuffer(uint32_t event, uint32_t pkt_size, uint32_t data_len) {
  std::vector<char> buf(sizeof(event_metadata) + data_len, 'x');
  event_metadata mdata{event, pkt_size, data_len};
  std::memcpy(buf.data(), &mdata, sizeof(event_metadata));
  return buf;
}

} // namespace

TEST(KatranEventReaderTest, PerfBufferCapacityUses4KUnits) {
  EXPECT_EQ(detail::getPerfBufferPageCount(32, 4096), 32);
  EXPECT_EQ(detail::getPerfBufferPageCount(32, 16384), 8);
  EXPECT_EQ(detail::getPerfBufferPageCount(32, 65536), 2);
  EXPECT_EQ(detail::getPerfBufferPageCount(256, 65536), 16);
  EXPECT_EQ(detail::getPerfBufferPageCount(2, 65536), 1);
  EXPECT_EQ(detail::getPerfBufferPageCount(1, 16384), 1);
}

TEST(KatranEventReaderTest, InvalidPerfBufferSizingRejected) {
  EXPECT_EQ(detail::getPerfBufferPageCount(0, 4096), 0);
  EXPECT_EQ(detail::getPerfBufferPageCount(3, 4096), 0);
  EXPECT_EQ(detail::getPerfBufferPageCount(32, 0), 0);
  EXPECT_EQ(detail::getPerfBufferPageCount(32, 6144), 0);
  const auto overflowingPages = std::numeric_limits<size_t>::max() / 2 + 1;
  EXPECT_EQ(detail::getPerfBufferPageCount(overflowingPages, 65536), 0);
}

TEST(KatranEventReaderTest, TooShortBufferDropped) {
  auto queue = makeQueue();
  KatranEventReader reader(queue);
  char tiny[1] = {};
  reader.handlePerfBufferEvent(0, tiny, 0);
  PcapMsgMeta result;
  EXPECT_FALSE(queue->read(result));
}

TEST(KatranEventReaderTest, ValidEventEnqueued) {
  auto queue = makeQueue();
  KatranEventReader reader(queue);
  auto buf = makeBuffer(0, 10, 5);
  reader.handlePerfBufferEvent(0, buf.data(), buf.size());
  PcapMsgMeta result;
  ASSERT_TRUE(queue->read(result));
  EXPECT_EQ(result.getPcapMsg().getOrigLen(), 10u);
  EXPECT_EQ(result.getPcapMsg().getCapturedLen(), 5u);
}

TEST(KatranEventReaderTest, EventIdPropagatedToMeta) {
  auto queue = makeQueue();
  KatranEventReader reader(queue);
  auto buf = makeBuffer(
      static_cast<uint32_t>(monitoring::EventId::TCP_NONSYN_LRUMISS), 4, 4);
  reader.handlePerfBufferEvent(0, buf.data(), buf.size());
  PcapMsgMeta result;
  ASSERT_TRUE(queue->read(result));
  EXPECT_EQ(result.getEventId(), monitoring::EventId::TCP_NONSYN_LRUMISS);
}

TEST(KatranEventReaderTest, QueueFullMessageDropped) {
  auto queue = makeQueue(1);
  KatranEventReader reader(queue);
  auto buf = makeBuffer(0, 4, 4);
  // fill the queue
  reader.handlePerfBufferEvent(0, buf.data(), buf.size());
  EXPECT_EQ(queue->size(), 1u);
  // second write should fail silently — no crash
  reader.handlePerfBufferEvent(0, buf.data(), buf.size());
  EXPECT_EQ(queue->size(), 1u);
}

TEST(KatranEventReaderTest, ExactlyMinSizeBuffer) {
  // size == sizeof(event_metadata) with pkt_size=6, data_len=0: enqueued
  auto queue = makeQueue();
  KatranEventReader reader(queue);
  auto buf = makeBuffer(0, 6, 0);
  reader.handlePerfBufferEvent(0, buf.data(), buf.size());
  PcapMsgMeta result;
  ASSERT_TRUE(queue->read(result));
  EXPECT_EQ(result.getPcapMsg().getOrigLen(), 6u);
  EXPECT_EQ(result.getPcapMsg().getCapturedLen(), 0u);
}

} // namespace katran
