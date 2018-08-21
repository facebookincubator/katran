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

#include "XdpEventLogger.h"

#include <folly/Conv.h>
#include <folly/IPAddress.h>
#include <glog/logging.h>

extern "C" {
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
}

namespace xdpdump {

namespace {

constexpr uint8_t kIPv6AddrSize = 16;
}

std::string XdpEventLogger::binaryToV6String(uint8_t const *v6) {
  folly::ByteRange bytes(v6, kIPv6AddrSize);
  return folly::IPAddressV6::fromBinary(bytes).str();
}

std::string XdpEventLogger::longToV4String(uint32_t v4) {
  return folly::IPAddressV4::fromLong(v4).str();
}

XdpEventInfo ProgLogger::handlePerfEvent(const char *data) {
  auto msg = reinterpret_cast<const XdpDumpOutput *>(data);
  XdpEventInfo info;
  info.pkt_size = msg->pkt_size;
  info.data_len = msg->data_len;
  info.hdr_size = sizeof(struct XdpDumpOutput);
  if (!mute_) {
    log(msg);
  }
  return info;
}

void ProgLogger::log(const XdpDumpOutput *msg) {
  if (msg->ipv6) {
    out_ << "srcv6: " << binaryToV6String((uint8_t *)&msg->srcv6)
         << " dstv6: " << binaryToV6String((uint8_t *)&msg->dstv6) << std::endl;
  } else {
    out_ << "src: " << longToV4String(msg->src)
         << " dst: " << longToV4String(msg->dst) << std::endl;
  }
  out_ << "proto: " << (uint16_t)msg->proto << " sport: " << ntohs(msg->sport)
       << " dport: " << ntohs(msg->dport) << " pkt size: " << msg->pkt_size
       << " chunk size: " << msg->data_len << std::endl;
}

} // namespace xdpdump
