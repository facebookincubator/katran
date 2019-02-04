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

#include <folly/io/IOBuf.h>

#include "Base64Helpers.h"

namespace katran {

TEST(Base64Tests, testEncode) {
  auto test_string = "Test Data!";
  auto buf = folly::IOBuf::copyBuffer(test_string);
  ASSERT_STREQ(
      Base64Helpers::base64Encode(buf.get()).c_str(), "VGVzdCBEYXRhIQ==");
};

TEST(Base64Tests, testDecode) {
  ASSERT_STREQ(
      Base64Helpers::base64Decode("VGVzdCBEYXRhIQ==").c_str(), "Test Data!");
};

} // namespace katran


int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

