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

#include <cstring>

#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <folly/io/IOBuf.h>
#include <glog/logging.h>

namespace katran {

std::string Base64Helpers::base64Encode(folly::IOBuf* buf) {
  using namespace boost::archive::iterators;
  using b64it = base64_from_binary<transform_width<const uint8_t*, 6, 8>>;
  int output_size = (buf->length() * 8 + 5) / 6;
  std::string encoded(output_size, '*');
  auto data = new char[buf->length()];
  if (data == nullptr) {
    // return empty string. as we are using this in tests only that would just
    // mean that we have failed a test. log line will show reason why.
    LOG(ERROR) << "Memory allocation during base64 encodingf failed";
    return "";
  }
  std::memcpy(data, buf->data(), buf->length());
  std::copy(b64it(data), b64it((char*)data + (buf->length())), encoded.begin());
  for (int i = 0; i < (3 - (buf->length() % 3)) % 3; i++) {
    encoded.push_back('=');
  }
  delete[] data;
  return encoded;
}

std::string Base64Helpers::base64Decode(std::string encoded) {
  using namespace boost::archive::iterators;
  using b64it =
      transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;

  auto decoded =
      std::string(b64it(std::begin(encoded)), b64it(std::end(encoded)));
  int padded_chars = 0;
  while (true) {
    if (encoded[encoded.size() - 1] != '=') {
      return decoded.substr(0, decoded.size() - padded_chars);
    }
    encoded.pop_back();
    padded_chars++;
  }
}

} // namespace katran
