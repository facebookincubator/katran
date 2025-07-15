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

#include <folly/Optional.h>
#include <string>
#include "katran/lib/testing/tools/PacketBuilder.h"

namespace katran {

struct PacketAttributes {
  // Base-64 encoded value of the packet sent to Katran
  std::string inputPacket;

  // Human-readable description of the packet being sent
  std::string description;

  // Expected return value of the balancer bpf program. Example: "XDP_TX"
  std::string expectedReturnValue;

  // Base-64 encoded value of the packet we expect after passing
  // the input packet through Katran.
  std::string expectedOutputPacket;

  // We set this if we want to verify whether or not the packet was
  // routed through global lru
  std::optional<bool> routedThroughGlobalLru{std::nullopt};

  // Scapy command representation of the input packet for debugging
  std::string inputScapyCommand;

  // Scapy command representation of the expected output packet for debugging
  std::string expectedOutputScapyCommand;

  // PacketBuilder for input packet
  std::optional<katran::testing::PacketBuilder> inputPacketBuilder;

  // PacketBuilder for expected output packet
  std::optional<katran::testing::PacketBuilder> expectedOutputPacketBuilder;
};

} // namespace katran
