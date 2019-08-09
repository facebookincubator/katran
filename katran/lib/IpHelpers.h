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

#include <folly/IPAddress.h>
#include <string>

namespace katran {

/**
 * struct, which represent given ip address in
 * big endian uint32_t ([4]) format for v4(v6)
 */
struct beaddr {
  union {
    uint32_t daddr;
    uint32_t v6daddr[4];
  };
  uint8_t flags;
};

class IpHelpers {
public:
  /**
   * @param const string addr address to translate
   * @return struct beaddr representation of given address
   *
   * helper function to translate addr to it's be representation if format
   * of beaddr structure. this function could throw, if given string is not
   * an ip address.
   */
  static struct beaddr parseAddrToBe(const std::string &addr,
                                     bool bigendian = true);
  static struct beaddr parseAddrToInt(const std::string &addr);

  static struct beaddr parseAddrToBe(const folly::IPAddress &addr,
                                     bool bigendian = true);
  static struct beaddr parseAddrToInt(const folly::IPAddress &addr);
};

} // namespace katran
