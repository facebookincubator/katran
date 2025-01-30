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

#include "IpHelpers.h"

#include <folly/lang/Bits.h>

namespace katran {

constexpr int Uint32_bytes = 4;
constexpr uint8_t V6DADDR = 1;

struct beaddr IpHelpers::parseAddrToBe(
    const std::string& addr,
    bool bigendian) {
  return parseAddrToBe(folly::IPAddress(addr), bigendian);
}

struct beaddr IpHelpers::parseAddrToBe(
    const folly::IPAddress& addr,
    bool bigendian) {
  struct beaddr translated_addr = {};
  if (addr.isV4()) {
    translated_addr.flags = 0;
    if (bigendian) {
      translated_addr.daddr = addr.asV4().toLong();
    } else {
      translated_addr.daddr = addr.asV4().toLongHBO();
    }
  } else {
    for (int partition = 0; partition < 4; partition++) {
      // bytes() return a ptr to char* array
      // so we are doing some ptr arithmetics here
      uint32_t addr_part =
          *(uint32_t*)(addr.bytes() + Uint32_bytes * partition);
      if (bigendian) {
        translated_addr.v6daddr[partition] = addr_part;
      } else {
        translated_addr.v6daddr[partition] = folly::Endian::big(addr_part);
      }
    }
    translated_addr.flags = V6DADDR;
  }
  return translated_addr;
}

struct beaddr IpHelpers::parseAddrToInt(const std::string& addr) {
  return parseAddrToBe(addr, false);
}

struct beaddr IpHelpers::parseAddrToInt(const folly::IPAddress& addr) {
  return parseAddrToBe(addr, false);
}

} // namespace katran
