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

#include "katran/lib/MacHelpers.h"

namespace katran {

TEST(MacHelpersTests, convertMacToUintValid) {
  const std::vector<uint8_t> expected{0x00, 0x11, 0x22, 0xaa, 0xbb, 0xcc};
  EXPECT_EQ(convertMacToUint("00:11:22:aa:bb:cc"), expected);
}

TEST(MacHelpersTests, convertMacToUintIsCaseInsensitive) {
  EXPECT_EQ(
      convertMacToUint("DE:AD:BE:EF:01:02"),
      convertMacToUint("de:ad:be:ef:01:02"));
}

TEST(MacHelpersTests, convertMacToUintInvalidReturnsZeroes) {
  // On parse failure, convertMacToUint swallows the exception and
  // returns a zero-initialized 6-byte vector.
  const std::vector<uint8_t> expected(6, 0);
  EXPECT_EQ(convertMacToUint("not a mac address"), expected);
}

TEST(MacHelpersTests, convertMacToUintEmptyStringReturnsZeroes) {
  const std::vector<uint8_t> expected(6, 0);
  EXPECT_EQ(convertMacToUint(""), expected);
}

TEST(MacHelpersTests, convertMacToUintTooShortReturnsZeroes) {
  const std::vector<uint8_t> expected(6, 0);
  EXPECT_EQ(convertMacToUint("00:11:22"), expected);
}

TEST(MacHelpersTests, convertMacToStringValid) {
  const std::vector<uint8_t> mac{0x00, 0x11, 0x22, 0xaa, 0xbb, 0xcc};
  EXPECT_EQ(convertMacToString(mac), "00:11:22:aa:bb:cc:");
}

TEST(MacHelpersTests, convertMacToStringAllZeroes) {
  const std::vector<uint8_t> mac(6, 0);
  EXPECT_EQ(convertMacToString(mac), "00:00:00:00:00:00:");
}

TEST(MacHelpersTests, convertMacToStringAllMax) {
  const std::vector<uint8_t> mac(6, 0xff);
  EXPECT_EQ(convertMacToString(mac), "ff:ff:ff:ff:ff:ff:");
}

TEST(MacHelpersTests, convertMacToStringWrongSizeReturnsUnknown) {
  EXPECT_EQ(convertMacToString({0x01, 0x02, 0x03, 0x04, 0x05}), "unknown");
  EXPECT_EQ(
      convertMacToString({0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}),
      "unknown");
}

TEST(MacHelpersTests, convertMacToStringEmptyReturnsUnknown) {
  EXPECT_EQ(convertMacToString({}), "unknown");
}

TEST(MacHelpersTests, stringToUintRoundTrip) {
  // The string->uint direction is reversible (modulo the trailing colon
  // that convertMacToString appends). Verifying the byte vector survives
  // a string->uint->string->uint round-trip catches any silent corruption.
  const std::string input = "01:23:45:67:89:ab";
  const auto bytes = convertMacToUint(input);
  const auto reformatted = convertMacToString(bytes);
  EXPECT_EQ(reformatted, input + ":");
  EXPECT_EQ(
      convertMacToUint(reformatted.substr(0, reformatted.size() - 1)), bytes);
}

} // namespace katran
