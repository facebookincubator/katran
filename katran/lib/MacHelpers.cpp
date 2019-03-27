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

#include <folly/Format.h>
#include <folly/MacAddress.h>

namespace katran {

std::vector<uint8_t> convertMacToUint(std::string macAddress) {
  std::vector<uint8_t> mac(6);

  folly::MacAddress default_mac;
  try {
    default_mac.parse(macAddress);
  } catch (const std::exception& e) {
    LOG(INFO) << "Exception: " << e.what() << std::endl;
    return mac;
  }

  auto mac_bytes = default_mac.bytes();
  for (int i = 0; i < 6; i++) {
    mac[i] = mac_bytes[i];
  }
  return mac;
};

std::string convertMacToString(std::vector<uint8_t> mac) {
  if (mac.size() != 6) {
    return "unknown";
  }
  uint16_t mac_part;
  std::string mac_part_string;
  std::string mac_string;
  for (auto m : mac) {
    mac_part = m;
    mac_part_string = folly::sformat("{0:02x}:", mac_part);
    mac_string += mac_part_string;
  }
  return mac_string;
};

} // namespace katran
