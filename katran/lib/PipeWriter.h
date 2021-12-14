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

#include <folly/io/async/AsyncPipe.h>
#include <folly/io/async/AsyncSocketException.h>
#include <cstdint>
#include "katran/lib/DataWriter.h"

namespace katran {

class PipeWriteCallback : public folly::AsyncWriter::WriteCallback {
 public:
  void writeSuccess() noexcept override {
    event_writes_++;
  }

  void writeErr(size_t, const folly::AsyncSocketException& e) noexcept
      override {
    LOG(ERROR) << "PipeWriter error: " << e.what();
    event_errs_++;
  }

  void reset() {
    event_writes_ = 0;
    event_errs_ = 0;
  }

  uint32_t event_writes_{0};
  uint32_t event_errs_{0};
};

/**
 * PipeWriter is used to write pcap-data into a pipe.
 */
class PipeWriter : public DataWriter {
 public:
  /**
   * Initialize writer without pipe, writer will silently discard all data
   * except header
   */
  explicit PipeWriter();

  /**
   * Write data to the pipe if it's writable
   */
  void writeData(const void* ptr, std::size_t size) override;

  /**
   * Save a copy of header and write data to pipe
   */
  void writeHeader(const void* ptr, std::size_t size) override;

  /**
   * PipeWriter doesn not have storage on its own, so always available to write
   * more
   */
  bool available(std::size_t /* unused */) override {
    return true;
  }

  /**
   * restart the writer
   */
  bool restart() override {
    VLOG(4) << "Retsarting pipe writer";
    enabled_ = true;
    return true;
  }

  /**
   * stop the writer by closing the pipe
   */
  bool stop() override {
    VLOG(4) << "Stopping pipe writer";
    enabled_ = false;
    return true;
  }

  /**
   * Change the destination of writer
   */
  void setWriterDestination(std::shared_ptr<folly::AsyncPipeWriter> pipeWriter);

  /**
   * Remove the writer's detination
   * As a result, writer will discard all messages from this point forward
   */
  void unsetWriterDestination();

  /**
   * Get the number of writes
   */
  uint32_t getWrites() {
    return writeCallback_.event_writes_;
  }

  /**
   * Get the number of errors
   */
  uint32_t getErrs() {
    return writeCallback_.event_errs_;
  }

 private:
  /**
   * The write side of the pipe
   */
  std::shared_ptr<folly::AsyncPipeWriter> pipe_;

  /**
   * Flag to enable writing to pipe
   */
  bool enabled_{true};

  /**
   * Writer callback
   */
  PipeWriteCallback writeCallback_;

  /**
   * Header buffer
   */
  std::unique_ptr<folly::IOBuf> headerBuf_{nullptr};
};

} // namespace katran
