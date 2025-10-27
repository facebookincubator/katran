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
using EventId = monitoring::EventId;
constexpr EventId kDefaultWriter = EventId::TCP_NONSYN_LRUMISS;
} // namespace

PcapWriter::PcapWriter(
    std::shared_ptr<DataWriter> dataWriter,
    uint32_t packetLimit,
    uint32_t snaplen)
    : packetLimit_(packetLimit), snaplen_(snaplen) {
  dataWriters_.insert({kDefaultWriter, dataWriter});
}

PcapWriter::PcapWriter(
    std::unordered_map<EventId, std::shared_ptr<DataWriter>>& dataWriters,
    uint32_t packetLimit,
    uint32_t snaplen)
    : dataWriters_(dataWriters), packetLimit_(packetLimit), snaplen_(snaplen) {}

void PcapWriter::writePacket(const PcapMsg& msg, EventId writerId) {
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
  auto writerIt = dataWriters_.find(writerId);
  if (writerIt == dataWriters_.end()) {
    LOG(ERROR) << "no writer w/ specified ID: " << writerId;
    return;
  }
  writerIt->second->writeData(&rec_hdr, sizeof(rec_hdr));
  writerIt->second->writeData(msg.getRawBuffer(), msg.getCapturedLen());
}

bool PcapWriter::writePcapHeader(EventId writerId) {
  if (headerExists_.find(writerId) != headerExists_.end()) {
    VLOG(4) << "header already exists";
    return true;
  }
  auto writerIt = dataWriters_.find(writerId);
  if (writerIt == dataWriters_.end()) {
    LOG(ERROR) << "No writer w/ specified ID: " << writerId;
    return false;
  }
  if (!writerIt->second->available(sizeof(struct pcap_hdr_s))) {
    LOG(ERROR) << "DataWriter failed to write a header. Not enough space.";
    return false;
  }
  struct pcap_hdr_s hdr{
      .magic_number = kPcapWriterMagic,
      .version_major = kVersionMajor,
      .version_minor = kVersionMinor,
      .thiszone = kGmt,
      .sigfigs = kAccuracy,
      .snaplen = snaplen_ ?: kMaxSnapLen,
      .network = kEthernet};
  writerIt->second->writeHeader(&hdr, sizeof(hdr));
  headerExists_.insert(writerId);
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
    auto writerIt = dataWriters_.find(kDefaultWriter);
    if (writerIt == dataWriters_.end()) {
      LOG(ERROR) << "No writer w/ specified Id: " << kDefaultWriter;
    }
    if (!writerIt->second->available(
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
  headerExists_.clear();

  for (auto& eventAndWriter : dataWriters_) {
    eventAndWriter.second->restart();
  }

  packetLimit_ = packetLimit;
  packetAmount_ = 0;
}

void PcapWriter::stopWriters() {
  for (auto& eventAndWriter : dataWriters_) {
    eventAndWriter.second->stop();
  }
  packetLimit_ = 0;
  packetAmount_ = packetLimit_;
}

void PcapWriter::resetWriters(
    std::unordered_map<monitoring::EventId, std::shared_ptr<DataWriter>>&&
        newDataWriters) {
  // Writers should have been stopped
  Guard lock(cntrLock_);
  // Gracefully stop
  for (auto& eventAndWriter : dataWriters_) {
    eventAndWriter.second->stop();
  }
  dataWriters_.clear();
  dataWriters_ = std::move(newDataWriters);
}

void PcapWriter::runMulti(
    std::shared_ptr<folly::MPMCQueue<PcapMsgMeta>> queue) {
  auto snaplen = snaplen_ ?: kMaxSnapLen;
  PcapMsgMeta msg;
  for (;;) {
    VLOG(4) << __func__ << " blockingRead msg";
    queue->blockingRead(msg);
    Guard lock(cntrLock_);
    if (msg.isControl()) {
      if (msg.isShutdown()) {
        VLOG(4) << "Shutdown message was received. Stopping.";
        break;
      } else if (msg.isRestart()) {
        VLOG(4) << "Restart message was received. Restarting.";
        restartWriters(msg.getLimit());
      } else if (msg.isStop()) {
        VLOG(4) << "Stop message was received. Stopping.";
        stopWriters();
      }
      continue;
    }
    if (!packetLimitOverride_ && packetAmount_ >= packetLimit_) {
      VLOG(4)
          << "No packetLimitOverride and packetAmount is greater than packetLimit. Skipping";
      continue;
    }
    auto eventId = msg.getEventId();
    if (enabledEvents_.find(eventId) == enabledEvents_.end()) {
      LOG(INFO) << "event " << eventId << " is not enabled, skipping";
      continue;
    }
    if (!writePcapHeader(eventId)) {
      LOG(ERROR) << "DataWriter failed to write a header";
      continue;
    }
    msg.getPcapMsg().trim(snaplen);
    auto writerIt = dataWriters_.find(eventId);
    if (writerIt == dataWriters_.end()) {
      LOG(ERROR) << "No writer w/ specified Id: " << eventId;
      continue;
    }
    if (!writerIt->second->available(
            msg.getPcapMsg().getCapturedLen() + sizeof(pcaprec_hdr_s))) {
      VLOG(4) << "Writer buffer is full. Skipping";
      ++bufferFull_;
      continue;
    }
    VLOG(4) << __func__ << " write packet for event: " << eventId;
    writePacket(msg.getPcapMsg(), eventId);
    ++packetAmount_;
  }
}

} // namespace katran
