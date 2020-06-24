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
#include <folly/io/async/ScopedEventBaseThread.h>

#include "katran/lib/FileWriter.h"
#include "katran/lib/IOBufWriter.h"
#include "katran/lib/PipeWriter.h"
#include "katran/lib/KatranEventReader.h"

namespace katran {

namespace {
constexpr uint32_t kNoSample = 1;
}

KatranMonitor::KatranMonitor(const KatranMonitorConfig& config)
    : config_(config) {
  scopedEvb_ = std::make_unique<folly::ScopedEventBaseThread>("katran_monitor");
  queue_ = std::make_shared<folly::MPMCQueue<PcapMsgMeta>>(
    config_.queueSize);
  auto evb = scopedEvb_->getEventBase();
  for (int cpu = 0; cpu < config_.nCpus; cpu++) {
    auto reader =
        std::make_unique<KatranEventReader>(config_.pages, cpu, queue_);
    if (!reader->open(config_.mapFd, evb, kNoSample)) {
      LOG(ERROR) << "Perf event queue init failed for cpu: " << cpu;
    } else {
      readers_.push_back(std::move(reader));
    }
  }
  if (readers_.size() == 0) {
    throw std::runtime_error("none of eventReaders were initialized");
  }

std::vector<std::shared_ptr<DataWriter>> data_writers;
  for (int i = 0; i < config_.maxEvents; i++) {
    if (config_.storage == PcapStorageFormat::FILE) {
      std::string fname;
      folly::toAppend(config_.path, "_", i, &fname);
      data_writers.push_back(std::make_shared<FileWriter>(fname));
    } else if (config_.storage == PcapStorageFormat::IOBUF) {
      buffers_.emplace_back(folly::IOBuf::create(config_.bufferSize));
      data_writers.push_back(
        std::make_shared<IOBufWriter>(buffers_.back().get()));
    } else {
      // PcapStorageFormat::PIPE
      data_writers.push_back(std::make_shared<PipeWriter>());
    }
  }

  writer_ = std::make_shared<PcapWriter>(
      data_writers, config_.pcktLimit, config_.snapLen);
  // Enable all events
  for (int i = 0; i < config_.maxEvents; i++) {
    enableWriterEvent(i);
  }
  writerThread_ = std::thread([this](){writer_->runMulti(queue_);});

}

KatranMonitor::~KatranMonitor(){
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

void KatranMonitor::restartMonitor(uint32_t limit) {
  PcapMsgMeta msg;
  msg.setControl(true);
  msg.setRestart(true);
  msg.setLimit(limit);
  queue_->blockingWrite(std::move(msg));
}

bool KatranMonitor::enableWriterEvent(uint32_t event) {
  if (!writer_ || event >= config_.maxEvents) {
    return false;
  }
  return writer_->enableEvent(event);
}

std::set<uint32_t> KatranMonitor::getWriterEnabledEvents() {
  if (!writer_) {
    return {};
  }
  return writer_->getEnabledEvents();
}

bool KatranMonitor::disableWriterEvent(uint32_t event) {
  if (!writer_ || event >= config_.maxEvents) {
    return false;
  }
  writer_->disableEvent(event);
  return true;
}

std::unique_ptr<folly::IOBuf> KatranMonitor::getEventBuffer(int event) {
  if (buffers_.size() == 0) {
    LOG(ERROR) << "PcapStorageFormat is not set to IOBuf";
    return nullptr;
  }
  if (event < 0 || event > (buffers_.size() - 1)) {
    LOG(ERROR) << "Undefined event id";
    return nullptr;
  }
  return buffers_[event]->cloneOne();
}

void KatranMonitor::setAsyncPipeWriter(uint32_t event, std::shared_ptr<folly::AsyncPipeWriter> writer) {
  if (event > config_.maxEvents) {
    LOG(ERROR) << "event id exceeds maxEvents";
    return;
  }
  // If either casting or getDataWriter() fails, pipeWriter will be nullptr
  auto pipeWriter = std::dynamic_pointer_cast<PipeWriter>(writer_->getDataWriter(event));
  if (!pipeWriter) {
    LOG(ERROR) << "no pipe writer for event " << event;
    return;
  }
  pipeWriter->setWriterDestination(writer);
  writer_->enableEvent(event);
}

void KatranMonitor::unsetAsyncPipeWriter(uint32_t event) {
  if (event > config_.maxEvents) {
    LOG(ERROR) << "event id exceeds maxEvents";
    return;
  }
  auto pipeWriter = std::dynamic_pointer_cast<PipeWriter>(writer_->getDataWriter(event));
  if (!pipeWriter) {
    LOG(ERROR) << "no pipe writer for event " << event;
    return;
  }
  writer_->disableEvent(event);
  pipeWriter->unsetWriterDestination();
}

PcapWriterStats KatranMonitor::getWriterStats() {
  return writer_->getStats();
}

} // namespace katran
