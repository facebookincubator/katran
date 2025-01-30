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
#include "katran/lib/PcapMsgMeta.h"
#include <fmt/core.h>

namespace katran {

using EventId = monitoring::EventId;

PcapMsgMeta::PcapMsgMeta(PcapMsg&& msg, uint32_t event)
    : msg_(std::move(msg)), event_(event) {}

PcapMsgMeta::PcapMsgMeta(PcapMsgMeta&& msg) noexcept
    : msg_(std::move(msg.msg_)),
      event_(msg.event_),
      packetLimit_(msg.packetLimit_),
      restart_(msg.restart_),
      control_(msg.control_),
      stop_(msg.stop_),
      shutdown_(msg.shutdown_) {}

PcapMsgMeta& PcapMsgMeta::operator=(PcapMsgMeta&& msg) noexcept {
  msg_ = std::move(msg.msg_);
  event_ = msg.event_;
  packetLimit_ = msg.packetLimit_;
  restart_ = msg.restart_;
  control_ = msg.control_;
  stop_ = msg.stop_;
  shutdown_ = msg.shutdown_;
  return *this;
}

PcapMsg& PcapMsgMeta::getPcapMsg() {
  return msg_;
}

EventId PcapMsgMeta::getEventId() {
  try {
    return static_cast<EventId>(event_);
  } catch (const std::exception& e) {
    LOG(ERROR) << fmt::format("invalid event {}: {}", event_, e.what());
    return EventId::UNKNOWN;
  }
}

} // namespace katran
