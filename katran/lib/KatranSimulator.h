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

#include <folly/io/IOBuf.h>
#include <folly/io/async/ScopedEventBaseThread.h>
#include <memory>
#include <string>

namespace katran {

/**
 * struct that contains all the fields that uniquely identifies a flow
 */
struct KatranFlow {
  // source ip address of the packet
  std::string src;
  // destination ip address of the packet
  std::string dst;
  uint16_t srcPort;
  uint16_t dstPort;
  // protocol number (e.g. 6 for TCP, 17 for UDP)
  uint8_t proto;
};

/**
 * KatranSimulator allows end user to simulate what is going to happen
 * with specified packet after it is processed by katran load balancer.
 * For e.g. where (address of the real) this packet is going to be sent
 */
class KatranSimulator final {
 public:
  /**
   * @param int progFd descriptor of katran xdp program
   */
  explicit KatranSimulator(int progFd);
  ~KatranSimulator();

  /**
   * @param KatranFlow& flow that we are interested in
   * @return string ip address of the real (or empty string if packet will not
   * be sent)
   *
   * getRealForFlow helps to determines where specific flow is going to be sent
   * by returning ip address of the real
   */
  const std::string getRealForFlow(const KatranFlow& flow);

  // runSimulation takes packet (in iobuf represenation) and
  // run it through katran bpf program. It returns a modified pckt, if the
  // result was XDP_TX or nullptr otherwise.
  std::unique_ptr<folly::IOBuf> runSimulation(
      std::unique_ptr<folly::IOBuf> pckt);

 private:
  std::unique_ptr<folly::IOBuf> runSimulationInternal(
      std::unique_ptr<folly::IOBuf> pckt);

  // Affinitize simulator evb thread to CPU 0.
  // This ensures that subsequent simulations run on the same CPU and hit
  // same per-CPU maps.
  void affinitizeSimulatorThread();

  int progFd_;
  folly::ScopedEventBaseThread simulatorEvb_{"KatranSimulator"};
};
} // namespace katran
