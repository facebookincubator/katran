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

#include <string>

namespace folly {
class IOBuf;
}

namespace katran {

/**
 * helper class to do base64 encoding/decoding.
 * built to be as simple as possible. only intented to be used in BpfTester
 */
class Base64Helpers {
 public:
  /**
   * @param IOBuf* buf pointer to memory, which we want to encode
   * @return string base64 encoded memory region, where buf was pointing to
   *
   * helper function to encode data, stored in IOBuf as base64 encoded string
   */
  static std::string base64Encode(folly::IOBuf* buf);

  /**
   * @param string encoded base64 encoded value
   * @return string decoded value
   *
   * helper function to decode base64 encoded string
   */
  static std::string base64Decode(std::string encoded);
};

} // namespace katran
