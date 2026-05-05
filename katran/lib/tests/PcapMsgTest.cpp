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

#include "katran/lib/PcapMsg.h"
#include "katran/lib/PcapMsgMeta.h"

#include <gtest/gtest.h>
#include <cstring>

namespace katran {

// ---- PcapMsg ----

TEST(PcapMsgTest, DefaultConstructor_IsEmptyMsg) {
  PcapMsg msg;
  EXPECT_TRUE(msg.emptyMsg());
}

TEST(PcapMsgTest, Construction_StoresLengths) {
  const char data[] = "hello";
  PcapMsg msg(data, 10, 5);
  EXPECT_EQ(msg.getOrigLen(), 10u);
  EXPECT_EQ(msg.getCapturedLen(), 5u);
}

TEST(PcapMsgTest, Construction_CopiesBytes) {
  const char data[] = "hello";
  PcapMsg msg(data, 5, 5);
  EXPECT_FALSE(msg.emptyMsg());
  EXPECT_EQ(std::memcmp(msg.getRawBuffer(), data, 5), 0);
}

TEST(PcapMsgTest, NullptrData_IsEmptyMsg) {
  PcapMsg msg(nullptr, 5, 5);
  EXPECT_TRUE(msg.emptyMsg());
}

TEST(PcapMsgTest, Trim_ClampsToSnaplen) {
  const std::string data(20, 'x');
  PcapMsg msg(data.data(), 20, 20);
  EXPECT_EQ(msg.trim(10), 10u);
  EXPECT_EQ(msg.getCapturedLen(), 10u);
}

TEST(PcapMsgTest, Trim_NoOpWhenShorterThanSnaplen) {
  const char data[] = "hi";
  PcapMsg msg(data, 5, 2);
  msg.trim(100);
  EXPECT_EQ(msg.getCapturedLen(), 2u);
}

TEST(PcapMsgTest, MoveConstructor_TransfersOwnership) {
  const char data[] = "data";
  PcapMsg original(data, 10, 4);
  PcapMsg moved(std::move(original));
  EXPECT_EQ(moved.getOrigLen(), 10u);
  EXPECT_EQ(moved.getCapturedLen(), 4u);
  EXPECT_FALSE(moved.emptyMsg());
}

TEST(PcapMsgTest, MoveAssignment_TransfersOwnership) {
  const char data[] = "data";
  PcapMsg original(data, 7, 4);
  PcapMsg other;
  other = std::move(original);
  EXPECT_EQ(other.getOrigLen(), 7u);
  EXPECT_EQ(other.getCapturedLen(), 4u);
  EXPECT_FALSE(other.emptyMsg());
}

// ---- PcapMsgMeta ----

TEST(PcapMsgMetaTest, DefaultConstructor_AllFlagsFalseAndLimitZero) {
  PcapMsgMeta meta;
  EXPECT_TRUE(meta.getPcapMsg().emptyMsg());
  EXPECT_FALSE(meta.isControl());
  EXPECT_FALSE(meta.isRestart());
  EXPECT_FALSE(meta.isStop());
  EXPECT_FALSE(meta.isShutdown());
  EXPECT_EQ(meta.getLimit(), 0u);
}

TEST(PcapMsgMetaTest, Construction_CastsEventId) {
  const char data[] = "pkt";
  PcapMsg msg(data, 3, 3);
  PcapMsgMeta meta(
      std::move(msg),
      static_cast<uint32_t>(monitoring::EventId::TCP_NONSYN_LRUMISS));
  EXPECT_EQ(meta.getEventId(), monitoring::EventId::TCP_NONSYN_LRUMISS);
}

TEST(PcapMsgMetaTest, FlagSetters_Roundtrip) {
  PcapMsgMeta meta;
  meta.setControl(true);
  meta.setRestart(true);
  meta.setStop(true);
  meta.setShutdown(true);
  meta.setLimit(42);
  EXPECT_TRUE(meta.isControl());
  EXPECT_TRUE(meta.isRestart());
  EXPECT_TRUE(meta.isStop());
  EXPECT_TRUE(meta.isShutdown());
  EXPECT_EQ(meta.getLimit(), 42u);
}

TEST(PcapMsgMetaTest, MoveConstructor_TransfersAllState) {
  const char data[] = "pkt";
  PcapMsg msg(data, 3, 3);
  PcapMsgMeta original(
      std::move(msg),
      static_cast<uint32_t>(monitoring::EventId::PACKET_TOOBIG));
  original.setControl(true);
  original.setLimit(99);

  PcapMsgMeta moved(std::move(original));
  EXPECT_FALSE(moved.getPcapMsg().emptyMsg());
  EXPECT_TRUE(moved.isControl());
  EXPECT_EQ(moved.getLimit(), 99u);
  EXPECT_EQ(moved.getEventId(), monitoring::EventId::PACKET_TOOBIG);
}

} // namespace katran
