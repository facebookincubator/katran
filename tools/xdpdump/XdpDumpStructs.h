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

namespace xdpdump {

struct XdpDumpFilter {
  union {
    uint32_t src;
    uint32_t srcv6[4];
  };
  union {
    uint32_t dst;
    uint32_t dstv6[4];
  };
  uint16_t sport;
  uint16_t dport;
  uint8_t proto;
  bool ipv6;
  uint16_t offset;
  uint16_t offset_len;
  uint32_t pattern;
  std::string map_path;
  uint8_t flags;
  uint64_t count;
  bool mute;
  int32_t cpu;
  int32_t pages;
};

extern "C" {
struct XdpDumpOutput {
  union {
    uint32_t src;
    uint32_t srcv6[4];
  };
  union {
    uint32_t dst;
    uint32_t dstv6[4];
  };
  bool ipv6;
  uint16_t sport;
  uint16_t dport;
  uint8_t proto;
  uint16_t pkt_size;
  uint16_t data_len;
};
}
} // namespace xdpdump
