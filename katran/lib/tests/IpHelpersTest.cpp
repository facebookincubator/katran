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

#include "katran/lib/IpHelpers.h"

namespace katran {

TEST(IpHelpersTests, testV4ParsingBe) {
  auto addr = IpHelpers::parseAddrToBe("1.1.1.2");
  // check that flags are cleared
  ASSERT_EQ(addr.flags, 0);
  ASSERT_EQ(addr.daddr, 33620225);
}

TEST(IpHelpersTests, testV4ParsingInt) {
  auto addr = IpHelpers::parseAddrToInt("1.1.1.2");
  // check that flags are cleared
  ASSERT_EQ(addr.flags, 0);
  ASSERT_EQ(addr.daddr, 16843010);
}

TEST(IpHelpersTests, testV6ParsingBe) {
  auto addr = IpHelpers::parseAddrToBe("2401:db00:f01c:2002:face:0:d:0");
  // checking that flags field is equal to 1 (to show that this is ipv6)
  ASSERT_EQ(addr.flags, 1);
  ASSERT_EQ(addr.v6daddr[0], 14352676);
  ASSERT_EQ(addr.v6daddr[1], 35658992);
  ASSERT_EQ(addr.v6daddr[2], 52986);
  ASSERT_EQ(addr.v6daddr[3], 3328);
}

TEST(IpHelpersTests, testV6ParsingInt) {
  auto addr = IpHelpers::parseAddrToInt("2401:db00:f01c:2002:face:0:d:0");
  // checking that flags field is equal to 1 (to show that this is ipv6)
  ASSERT_EQ(addr.flags, 1);
  ASSERT_EQ(addr.v6daddr[0], 604101376);
  ASSERT_EQ(addr.v6daddr[1], 4028375042);
  ASSERT_EQ(addr.v6daddr[2], 4207804416);
  ASSERT_EQ(addr.v6daddr[3], 851968);
}

TEST(IpHelpersTests, testIncorrectAddr) {
  // we are testing that our parserAddrToBe throws on
  // incorrect input
  int i = 1;
  try {
    IpHelpers::parseAddrToBe("wrong address");
    i = 2;
  } catch (...) {
    i = 1;
  }
  ASSERT_EQ(i, 1);
}

} // namespace katran
