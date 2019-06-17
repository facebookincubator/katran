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
#include "katran/lib/PcapMsg.h"

namespace katran {

/**
 * PcapMsg with additional metadata
 */
class PcapMsgMeta {
 public:
  PcapMsgMeta(){}

  PcapMsgMeta(PcapMsg&& msg, uint32_t event);

  PcapMsgMeta(PcapMsgMeta&& msg) noexcept;

  PcapMsgMeta(const PcapMsgMeta& msg) = delete;

  ~PcapMsgMeta(){}

  PcapMsgMeta& operator=(PcapMsgMeta&& msg) noexcept;

  PcapMsgMeta& operator=(const PcapMsgMeta& msg) = delete;

  PcapMsg& getPcapMsg();

  bool isControl() {
    return control_;
  }

  void setControl(bool control) {
    control_ = control;
  }

  bool isRestart() {
    return restart_;
  }

  void setRestart(bool restart) {
    restart_ = restart;
  }

  bool isStop() {
    return stop_;
  }

  void setStop(bool stop) {
    stop_ = stop;
  }

  bool isShutdown() {
    return shutdown_;
  }

  void setShutdown(bool shutdown) {
    shutdown_ = shutdown;
  }

  uint32_t getLimit() {
    return packetLimit_;
  }

  void setLimit(uint32_t limit) {
    packetLimit_ = limit;
  }

  uint32_t getEventId();

 private:
  PcapMsg msg_;
  uint32_t event_{0};
  uint32_t packetLimit_{0};
  bool restart_{false};
  bool control_{false};
  bool stop_{false};
  bool shutdown_{false};
};

} // namespace katran
