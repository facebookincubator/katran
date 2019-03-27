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

#include "katran/decap/XdpDecapStructs.h"
#include "katran/lib/BpfAdapter.h"

namespace katran {

class XdpDecap {
 public:
  XdpDecap() = delete;
  /**
   * @param XdpDecapConfig& config main configuration of XdpDecap
   */
  explicit XdpDecap(const XdpDecapConfig& config);

  ~XdpDecap();

  /**
   * helper function to load decapsulator into kernel
   */
  void loadXdpDecap();

  /**
   * helper function to attach XdpDecap
   */
  void attachXdpDecap();

  /**
   * @return decap_stats main stats of XdpDecap
   *
   * helper function to get XdpDecap stats on how many packets were
   * decapsulated and processed (processed one contains both decapsulated and
   * passed as is)
   */
  decap_stats getXdpDecapStats();

  /**
   * @return int fd of loaded XdpDecap program
   *
   * helper function to get descriptor of XdpDecap program
   */
  int getXdpDecapFd() {
    return bpfAdapter_.getProgFdByName("xdp-decap");
  }

 private:
  /**
   * main configuration
   */
  XdpDecapConfig config_;

  /**
   * bpf adapter to interact w/ BPF subsystem
   */
  BpfAdapter bpfAdapter_;

  /**
   * flag which indicates were XdpDecap attached as standalone program or not
   * in standalone mode xdpdecap would try to install xdp program to physical
   * interface directly. in shared (!standalone) it would try to register itself
   * into provided bpf's program array on specified position
   */
  bool isStandalone_{true};

  /**
   * flag which indicate if XdpDecap were loaded into kernel or not
   */
  bool isLoaded_{false};

  /**
   * flag which indicates if XdpDecap were attached
   */
  bool isAttached_{false};
};

} // namespace katran
