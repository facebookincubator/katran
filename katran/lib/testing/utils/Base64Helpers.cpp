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

#include "katran/lib/testing/utils/Base64Helpers.h"

#include <string_view>

#include <folly/base64.h>
#include <folly/io/IOBuf.h>

namespace katran {

std::string Base64Helpers::base64Encode(folly::IOBuf* buf) {
  return folly::base64Encode(
      std::string_view(
          reinterpret_cast<const char*>(buf->data()), buf->length()));
}

std::string Base64Helpers::base64Decode(const std::string& encoded) {
  // base64URLDecode also reads the standard alphabet and, unlike base64Decode,
  // takes input without padding.
  return folly::base64URLDecode(encoded);
}

} // namespace katran
