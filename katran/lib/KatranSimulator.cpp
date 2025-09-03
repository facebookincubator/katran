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

#include "katran/lib/KatranSimulator.h"

#include <glog/logging.h>
#include <cstring>

#include "katran/lib/BpfAdapter.h"
#include "katran/lib/KatranSimulatorUtils.h"

extern "C" {
#include <linux/ipv6.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
}

namespace katran {

namespace {
constexpr uint16_t kMaxXdpPcktSize = 4096;
constexpr uint16_t kTestPacketSize = 512;
constexpr int kTestRepeatCount = 1;
constexpr uint8_t kDefaultTtl = 64;
constexpr folly::StringPiece kEmptyString = "";
} // namespace

KatranSimulator::KatranSimulator(int progFd) : progFd_(progFd) {
  affinitizeSimulatorThread();
}

KatranSimulator::~KatranSimulator() {}

std::unique_ptr<folly::IOBuf> KatranSimulator::runSimulation(
    std::unique_ptr<folly::IOBuf> pckt) {
  std::unique_ptr<folly::IOBuf> result;
  simulatorEvb_.getEventBase()->runInEventBaseThreadAndWait(
      [&]() { result = runSimulationInternal(std::move(pckt)); });
  return result;
}

std::unique_ptr<folly::IOBuf> KatranSimulator::runSimulationInternal(
    std::unique_ptr<folly::IOBuf> pckt) {
  CHECK(simulatorEvb_.getEventBase()->isInEventBaseThread());
  if (!pckt) {
    LOG(ERROR) << "packet is empty";
    return nullptr;
  }
  if (pckt->isChained()) {
    LOG(ERROR) << "Chained buffers are not supported";
    return nullptr;
  }
  if (pckt->length() > kMaxXdpPcktSize) {
    LOG(ERROR) << "packet is too big";
    return nullptr;
  }
  auto rpckt = folly::IOBuf::create(kMaxXdpPcktSize);
  if (!rpckt) {
    LOG(ERROR) << "not able to allocate memory for resulting packet";
    return rpckt;
  }
  uint32_t output_pckt_size{0};
  uint32_t prog_ret_val{0};
  auto res = BpfAdapter::testXdpProg(
      progFd_,
      kTestRepeatCount,
      pckt->writableData(),
      pckt->length(),
      rpckt->writableData(),
      &output_pckt_size,
      &prog_ret_val);
  if (res < 0) {
    LOG(ERROR) << "failed to run simulator";
    return nullptr;
  }
  if (prog_ret_val != XDP_TX) {
    return nullptr;
  }
  rpckt->append(output_pckt_size);
  return rpckt;
}

const std::string KatranSimulator::getRealForFlow(const KatranFlow& flow) {
  auto pckt = KatranSimulatorUtils::createPacketFromFlow(
      flow, kTestPacketSize, kDefaultTtl);
  if (!pckt) {
    return kEmptyString.data();
  }
  auto rpckt = runSimulation(std::move(pckt));
  if (!rpckt) {
    return kEmptyString.data();
  }
  return KatranSimulatorUtils::getPcktDst(rpckt);
}

void KatranSimulator::affinitizeSimulatorThread() {
  simulatorEvb_.getEventBase()->runInEventBaseThreadAndWait([]() {
    cpu_set_t cpuSet;
    CPU_ZERO(&cpuSet);
    CPU_SET(0, &cpuSet);
    pthread_t currentThread = pthread_self();
    auto ret =
        pthread_setaffinity_np(currentThread, sizeof(cpu_set_t), &cpuSet);
    if (ret != 0) {
      LOG(ERROR) << "Error while affinitizing simulator thread to CPU 0: "
                 << ret;
    }
  });
}

} // namespace katran
