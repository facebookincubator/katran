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

#include <stdint.h>
#include <string>
#include <vector>

namespace katran {
class NetlinkMessage {
 public:
  /**
   * Constructs a netlink message used to control the lifecycle of a BPF
   * program on the network scheduler.
   *
   * @param seq          Sequence number for message.
   * @param cmd          The rtnetlink command (refer to linux/rtnetlink.h)
   * @param flags        Netlink flags (refer to linux/netlink.h)
   * @param priority     Priority of message, used as major number in TC
   *                     handle.
   * @param prog_fd      FD of loaded BPF program.
   * @param ifindex      Network interface index
   * @param bpf_name     Name of bpf program (for identification purposes)
   * @param direction    Ingress or egress
   */
  static NetlinkMessage TC(
      unsigned seq,
      int cmd,
      unsigned flags,
      uint32_t priority,
      int prog_fd,
      unsigned ifindex,
      const std::string& bpf_name,
      int direction);

  /**
   * Constructs a netlink message used to attach clsact qdisk
   * to specified interface
   *
   * @param ifindex      Network interface index
   */
  static NetlinkMessage QD(unsigned ifindex);

  /**
   * Constructs a netlink message used to control the lifecycle of an XDP BPF
   * program on a given interface
   *
   * @param seq        Sequence number for the Netlink message
   * @param prog_fd    FD for the BPF program.
   * @param ifindex    Network interface index
   * @param flags      Optional XDP flags.
   */
  static NetlinkMessage
  XDP(unsigned seq, int prog_fd, unsigned ifindex, uint32_t flags);

  const uint8_t* data() const {
    return buf_.data();
  }

  size_t size() const {
    return buf_.size();
  }

  unsigned seq() const;

 private:
  NetlinkMessage();
  std::vector<uint8_t> buf_;
};
} // namespace katran
