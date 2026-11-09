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

#include <gtest/gtest.h>

#include <libmnl/libmnl.h>

extern "C" {
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
}

#include "katran/lib/Netlink.h"

namespace katran {

namespace {
uint32_t tcHandle(int cmd, unsigned int flags, uint32_t handle) {
  const auto msg = NetlinkMessage::TC(
      /*seq=*/1,
      cmd,
      flags,
      /*priority=*/1,
      /*prog_fd=*/-1,
      /*ifindex=*/1,
      "test",
      TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS),
      handle);
  const auto* nlh = reinterpret_cast<const struct nlmsghdr*>(msg.data());
  return static_cast<const struct tcmsg*>(mnl_nlmsg_get_payload(nlh))
      ->tcm_handle;
}
} // namespace

TEST(NetlinkTest, TcKeepsFullHandle) {
  EXPECT_EQ(
      tcHandle(RTM_NEWTFILTER, NLM_F_EXCL | NLM_F_CREATE, 0x00031234u),
      0x00031234u);
}

TEST(NetlinkTest, TcHandlesSharingLow16BitsStayDistinct) {
  const auto flags = NLM_F_EXCL | NLM_F_CREATE;
  const auto first = tcHandle(RTM_NEWTFILTER, flags, 0x00011234u);
  const auto second = tcHandle(RTM_NEWTFILTER, flags, 0x00031234u);
  EXPECT_EQ(first, 0x00011234u);
  EXPECT_EQ(second, 0x00031234u);
  EXPECT_NE(first, second);
}

TEST(NetlinkTest, TcDeleteNeverTurnsNonzeroHandleIntoZero) {
  EXPECT_EQ(tcHandle(RTM_DELTFILTER, 0, 0x00020000u), 0x00020000u);
  EXPECT_EQ(tcHandle(RTM_DELTFILTER, 0, 0), 0u);
}

} // namespace katran
