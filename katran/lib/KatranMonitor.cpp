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

#include "katran/lib/KatranMonitor.h"

#include <folly/Conv.h>
#include <folly/Utility.h>
#include <folly/io/async/ScopedEventBaseThread.h>

#include "katran/lib/FileWriter.h"
#include "katran/lib/IOBufWriter.h"
#include "katran/lib/KatranEventReader.h"
#include "katran/lib/MonitoringStructs.h"
#include "katran/lib/PipeWriter.h"

namespace katran {

using monitoring::EventId;

KatranMonitor::KatranMonitor(const KatranMonitorConfig& config)
    : config_(config) {
  scopedEvb_ = std::make_unique<folly::ScopedEventBaseThread>("katran_monitor");
  queue_ = std::make_shared<folly::MPMCQueue<PcapMsgMeta>>(config_.queueSize);
  auto evb = scopedEvb_->getEventBase();

  reader_ = std::make_unique<KatranEventReader>(queue_);
  if (!reader_->open(config_.mapFd, evb, config_.pages)) {
    LOG(ERROR) << "Perf event reader init failed";
  }

  auto data_writers = createWriters();

  writer_ = std::make_shared<PcapWriter>(
      data_writers, config_.pcktLimit, config_.snapLen);

  // No packet limit for pipe
  writer_->overridePacketLimit(config_.storage == PcapStorageFormat::PIPE);

  // Initialize all events.
  // This will not start event loop, but only mark all events as "enabled".
  for (auto event : config_.events) {
    enableWriterEvent(event);
  }
  writerThread_ = std::thread([this]() { writer_->runMulti(queue_); });
}

KatranMonitor::~KatranMonitor() {
  PcapMsgMeta msg;
  msg.setControl(true);
  msg.setShutdown(true);
  queue_->write(std::move(msg));
  writerThread_.join();
};

void KatranMonitor::stopMonitor() {
  PcapMsgMeta msg;
  msg.setControl(true);
  msg.setStop(true);
  queue_->blockingWrite(std::move(msg));
}

void KatranMonitor::restartMonitor(
    uint32_t limit,
    std::optional<PcapStorageFormat> storage) {
  if (storage.has_value() && config_.storage != *storage) {
    stopMonitor();
    config_.storage = *storage;
    writer_->resetWriters(createWriters());
    writer_->overridePacketLimit(config_.storage == PcapStorageFormat::PIPE);
  }
  PcapMsgMeta msg;
  msg.setControl(true);
  msg.setRestart(true);
  msg.setLimit(limit);
  queue_->blockingWrite(std::move(msg));
  VLOG(4) << __func__ << "Successfully restarted monitor";
}

bool KatranMonitor::enableWriterEvent(EventId event) {
  if (!writer_) {
    return false;
  }
  return writer_->enableEvent(event);
}

std::set<EventId> KatranMonitor::getWriterEnabledEvents() {
  if (!writer_) {
    return {};
  }
  return writer_->getEnabledEvents();
}

bool KatranMonitor::disableWriterEvent(EventId event) {
  if (!writer_) {
    return false;
  }
  writer_->disableEvent(event);
  return true;
}

std::unique_ptr<folly::IOBuf> KatranMonitor::getEventBuffer(EventId event) {
  if (buffers_.size() == 0) {
    LOG(ERROR) << "PcapStorageFormat is not set to IOBuf";
    return nullptr;
  }
  auto it = buffers_.find(event);
  if (it == buffers_.end()) {
    LOG(ERROR) << "Event not enabled";
    return nullptr;
  }
  return it->second->cloneOne();
}

void KatranMonitor::setAsyncPipeWriter(
    EventId event,
    std::shared_ptr<folly::AsyncPipeWriter> writer) {
  // Save this writer destination
  auto it = pipeWriterDests_.find(event);
  if (it == pipeWriterDests_.end()) {
    auto res_it = pipeWriterDests_.emplace(event, writer);
    CHECK(res_it.second) << "Fail to emplace write destination";
    it = res_it.first;
  } else {
    VLOG(4) << "removing existing pipewriter for event " << toString(event);
    it->second = writer;
  }

  // If either casting or getDataWriter() fails, pipeWriter will be nullptr
  auto pipeWriter =
      std::dynamic_pointer_cast<PipeWriter>(writer_->getDataWriter(event));
  if (!pipeWriter) {
    LOG(INFO) << "no pipe writer for event " << event;
    return;
  }
  pipeWriter->setWriterDestination(writer);
  writer_->enableEvent(event);
  VLOG(4) << __func__ << "Successfully set AsyncPipeWriter";
}

void KatranMonitor::unsetAsyncPipeWriter(EventId event) {
  auto pipeWriter =
      std::dynamic_pointer_cast<PipeWriter>(writer_->getDataWriter(event));
  if (!pipeWriter) {
    LOG(ERROR) << "no pipe writer for event " << event;
    return;
  }
  writer_->disableEvent(event);
  pipeWriter->unsetWriterDestination();
  pipeWriterDests_.erase(event);
  VLOG(4) << __func__ << "Successfully unset AsyncPipeWriter";
}

PcapWriterStats KatranMonitor::getWriterStats() {
  return writer_->getStats();
}

std::unordered_map<monitoring::EventId, std::shared_ptr<DataWriter>>
KatranMonitor::createWriters() {
  std::unordered_map<EventId, std::shared_ptr<DataWriter>> dataWriters;
  for (auto event : config_.events) {
    if (config_.storage == PcapStorageFormat::FILE) {
      std::string fname;
      folly::toAppend(config_.path, "_", event, &fname);
      dataWriters.insert({event, std::make_shared<FileWriter>(fname)});
    } else if (config_.storage == PcapStorageFormat::IOBUF) {
      auto res =
          buffers_.insert({event, folly::IOBuf::create(config_.bufferSize)});
      dataWriters.insert(
          {event, std::make_shared<IOBufWriter>(res.first->second.get())});
    } else if (config_.storage == PcapStorageFormat::PIPE) {
      // PcapStorageFormat::PIPE
      auto pipeWriter = std::make_shared<PipeWriter>();
      auto destIt = pipeWriterDests_.find(event);
      if (destIt != pipeWriterDests_.end()) {
        pipeWriter->setWriterDestination(destIt->second);
      }
      dataWriters.insert({event, std::move(pipeWriter)});
    } else {
      LOG(ERROR) << "Invalid pcap storage format: "
                 << static_cast<int>(config_.storage);
    }
  }
  VLOG(4) << __func__ << "Data writers created";
  return dataWriters;
}

} // namespace katran
