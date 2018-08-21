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

#include "XdpDumpStructs.h"
#include <ostream>

namespace xdpdump {

struct XdpEventInfo {
  uint32_t data_len{0};
  uint32_t hdr_size{0};
  uint32_t pkt_size{0};
};

class XdpEventLogger {
public:
  /**
   * @param bool mute set true if logger shouldn't write any data into out
   * @param std::ostream& out is an ostream where logs are saved
   *
   * Constructor for XdpEventLogger
   */
  explicit XdpEventLogger(bool mute, std::ostream &out)
      : mute_(mute), out_(out) {}

  /**
   * Virtual destructor
   */
  virtual ~XdpEventLogger() = default;

  /**
   * @param const char* data received from the XDP prog.
   *
   * Function that processes handleEvent, produces XdpEventInfo, and,
   * if required, logs some data.
   */
  virtual XdpEventInfo handlePerfEvent(const char *data) = 0;

protected:
  /*
   * @param uint8_t const* v6 is an array of 16 bytes
   *
   * Converts bytes of IPv6 address into the std::string
   */
  static std::string binaryToV6String(uint8_t const *v6);

  /*
   * @param uint32_t v4 is an IPv4 address
   *
   * Converts IPv4 address presented by uint32 into the std::string
   */
  static std::string longToV4String(uint32_t v4);

  /**
   * mute_ set true if logger shouldn't write any data into out_
   */
  const bool mute_{false};

  /**
   * out_ is a stream where all information will be logged in.
   */
  std::ostream &out_;
};

class ProgLogger : public XdpEventLogger {
public:
  /**
   * @param bool mute set if logger should write any data into out
   * @param std::ostream& out is an ostream where logs are saved
   *
   * Constructor for ProgLogger
   */
  ProgLogger(bool mute, std::ostream &out) : XdpEventLogger(mute, out) {}

  /**
   * @param const char* data received from the XDP prog.
   *
   * Overrides XdpEventLogger::handlePerfEvent
   */
  virtual XdpEventInfo handlePerfEvent(const char *data) override;

private:
  /**
   * @param XdpDumpOutput* msg
   *
   * Logs prog data
   */
  void log(const XdpDumpOutput *msg);
};
} // namespace xdpdump
