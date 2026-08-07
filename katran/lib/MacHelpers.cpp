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

#include "katran/lib/MacHelpers.h"

#include <glog/logging.h>

#include <folly/MacAddress.h>

namespace katran {

std::vector<uint8_t> convertMacToUint(const std::string& macAddress) {
  std::vector<uint8_t> mac(6);

  folly::MacAddress default_mac;
  try {
    default_mac.parse(macAddress);
  } catch (const std::exception& e) {
    LOG(ERROR) << "Exception: " << e.what() << std::endl;
    return mac;
  }

  auto mac_bytes = default_mac.bytes();
  for (int i = 0; i < 6; i++) {
    mac[i] = mac_bytes[i];
  }
  return mac;
}

std::string convertMacToString(std::vector<uint8_t> mac) {
  if (mac.size() != 6) {
    return "unknown";
  }
  std::string mac_string;
  for (size_t i = 0; i < mac.size(); i++) {
    if (i > 0) {
      mac_string += ":";
    }
    mac_string += fmt::format("{0:02x}", static_cast<uint16_t>(mac[i]));
  }
  return mac_string;
}

} // namespace katran
