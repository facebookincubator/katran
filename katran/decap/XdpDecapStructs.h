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

namespace katran {

namespace {
  std::string kDefaultMapPath = "";
  const int kDefaultProgPos = 8;
  std::string kDefaultInterface = "lo";
}

/**
 * structure which contains main statistics about XDP based decapsulation
 * @param uint64_t decap_v4 number of decapsulated ipip packets
 * @param uint64_t decap_v6 number of decapsulated ip(4|6)ip6 packets
 * @param uint64_t total total number of packets which was processed
 */
struct decap_stats {
  uint64_t decap_v4;
  uint64_t decap_v6;
  uint64_t total;
};

/**
 * @param string progPath path to bpf object file w/ xdpdecap program
 * @param string mapPath in shared mode - path to bpf prog array
 * @param int progPos in shared mode - position in prog array
 * @param string interface in standalone mode - interface to attach
 * @param bool detachOnExit - should we remove xdp prog from kernel on exit
 *
 * structure which contains main XdpDecap configuration
 */
struct XdpDecapConfig {
  std::string progPath;
  std::string mapPath = kDefaultMapPath;
  int progPos = kDefaultProgPos;
  std::string interface = kDefaultInterface;
  bool detachOnExit = true;
};

}
