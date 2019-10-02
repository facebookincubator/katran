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

#include "katran/lib/PcapWriter.h"

#include <chrono>
#include "katran/lib/PcapStructs.h"

using Guard = std::lock_guard<std::mutex>;

namespace katran {

namespace {
constexpr uint32_t kPcapWriterMagic = 0xa1b2c3d4;
constexpr uint16_t kVersionMajor = 2;
constexpr uint16_t kVersionMinor = 4;
constexpr int32_t kGmt = 0;
constexpr uint32_t kAccuracy = 0;
constexpr uint32_t kMaxSnapLen = 0xFFFF; // 65535
constexpr uint32_t kEthernet = 1;
constexpr uint32_t kDefaultWriter = 0;
} // namespace

PcapWriter::PcapWriter(
    std::shared_ptr<DataWriter> dataWriter,
    uint32_t packetLimit,
    uint32_t snaplen)
    : packetLimit_(packetLimit), snaplen_(snaplen) {
  dataWriters_.push_back(dataWriter);
  headerExists_.push_back(false);
}

PcapWriter::PcapWriter(
    std::vector<std::shared_ptr<DataWriter>>& dataWriters,
    uint32_t packetLimit,
    uint32_t snaplen)
    : dataWriters_(dataWriters), packetLimit_(packetLimit), snaplen_(snaplen) {
  for (int i = 0; i < dataWriters_.size(); i++) {
    headerExists_.push_back(false);
  }
}

void PcapWriter::writePacket(const PcapMsg& msg, uint32_t writerId) {
  auto unix_usec =
      std::chrono::duration_cast<std::chrono::microseconds>(
          std::chrono::high_resolution_clock::now().time_since_epoch())
          .count();
  // 1sec = 1mil usec
  const uint32_t now_sec = unix_usec / 1000000;
  // in pcap format ts_usec is a offset in msec after ts_sec.
  const uint32_t now_usec = unix_usec - now_sec * 1000000;
  pcaprec_hdr_s rec_hdr{
      .ts_sec = now_sec,
      .ts_usec = now_usec,
  };
  rec_hdr.incl_len = msg.getCapturedLen();
  rec_hdr.orig_len = msg.getOrigLen();
  if (writerId >= dataWriters_.size()) {
    LOG(ERROR) << "no writer w/ specified ID: " << writerId;
    return;
  }
  dataWriters_[writerId]->writeData(&rec_hdr, sizeof(rec_hdr));
  dataWriters_[writerId]->writeData(msg.getRawBuffer(), msg.getCapturedLen());
}

bool PcapWriter::writePcapHeader(uint32_t writerId) {
  if (writerId >= dataWriters_.size()) {
    LOG(ERROR) << "no writer w/ specified ID: " << writerId;
    return false;
  }
  if (headerExists_[writerId]) {
    VLOG(4) << "header already exists";
    return true;
  }
  if (!dataWriters_[writerId]->available(sizeof(struct pcap_hdr_s))) {
    LOG(ERROR) << "DataWriter failed to write a header. Not enough space.";
    return false;
  }
  struct pcap_hdr_s hdr {
    .magic_number = kPcapWriterMagic, .version_major = kVersionMajor,
    .version_minor = kVersionMinor, .thiszone = kGmt, .sigfigs = kAccuracy,
    .snaplen = snaplen_ ?: kMaxSnapLen, .network = kEthernet
  };
  dataWriters_[writerId]->writeData(&hdr, sizeof(hdr));
  headerExists_[writerId] = true;
  return true;
}

void PcapWriter::run(std::shared_ptr<folly::MPMCQueue<PcapMsg>> queue) {
  auto snaplen = snaplen_ ?: kMaxSnapLen;
  if (!writePcapHeader(kDefaultWriter)) {
    LOG(ERROR) << "DataWriter failed to write a header";
    return;
  }
  PcapMsg msg(nullptr, 0, 0);
  while (packetLimit_ == 0 || packetAmount_ < packetLimit_) {
    queue->blockingRead(msg);
    Guard lock(cntrLock_);
    msg.trim(snaplen);
    if (msg.emptyMsg()) {
      LOG(INFO) << "Empty message was received. Writer thread is stopping.";
      break;
    }
    if (!dataWriters_[kDefaultWriter]->available(
            msg.getCapturedLen() + sizeof(pcaprec_hdr_s))) {
      ++bufferFull_;
      break;
    }
    writePacket(msg, kDefaultWriter);
    ++packetAmount_;
  }
}

PcapWriterStats PcapWriter::getStats() {
  PcapWriterStats stats;
  Guard lock(cntrLock_);
  stats.limit = packetLimit_;
  stats.amount = packetAmount_;
  stats.bufferFull = bufferFull_;
  return stats;
}

void PcapWriter::restartWriters(uint32_t packetLimit) {
  // as we are going to overrite all data writers. we would need to rewrite
  // headers
  for (int i = 0; i < headerExists_.size(); i++) {
    headerExists_[i] = false;
  }

  for (auto& writer : dataWriters_) {
    writer->restart();
  }

  packetLimit_ = packetLimit;
  packetAmount_ = 0;
}

void PcapWriter::stopWriters() {
  for (auto& writer : dataWriters_) {
    writer->stop();
  }
  packetLimit_ = 0;
  packetAmount_ = packetLimit_;
}

void PcapWriter::runMulti(
    std::shared_ptr<folly::MPMCQueue<PcapMsgMeta>> queue) {
  auto snaplen = snaplen_ ?: kMaxSnapLen;
  PcapMsgMeta msg;
  for (;;) {
    queue->blockingRead(msg);
    Guard lock(cntrLock_);
    if (msg.isControl()) {
      if (msg.isShutdown()) {
        LOG(INFO) << "Shutdown message was received. Stopping.";
        break;
      } else if (msg.isRestart()) {
        restartWriters(msg.getLimit());
      } else if (msg.isStop()) {
        stopWriters();
      }
      continue;
    }
    if (packetAmount_ >= packetLimit_) {
      continue;
    }
    if (!writePcapHeader(msg.getEventId())) {
      LOG(ERROR) << "DataWriter failed to write a header";
      continue;
    }
    msg.getPcapMsg().trim(snaplen);
    if (!dataWriters_[msg.getEventId()]->available(
            msg.getPcapMsg().getCapturedLen() + sizeof(pcaprec_hdr_s))) {
      ++bufferFull_;
      continue;
    }
    writePacket(msg.getPcapMsg(), msg.getEventId());
    ++packetAmount_;
  }
}

} // namespace katran
