// Copyright 2004-present Facebook. All Rights Reserved.

#include "katran/lib/PipeWriter.h"
#include <folly/io/IOBuf.h>
#include <cstring>

namespace katran {
PipeWriter::PipeWriter() {}

void PipeWriter::writeData(const void* ptr, std::size_t size) {
  VLOG_EVERY_N(4, 10) << __func__ << " write " << size << " bytes";

  if (size == 0) {
    LOG(ERROR) << "Zero-sized data. Skipping";
    return;
  }

  if (!enabled_) {
    VLOG_EVERY_N(4, 10) << "Disabled pipe writer. Skipping";
    return;
  }

  pipe_->write(&writeCallback_, ptr, size);
}

void PipeWriter::writeHeader(const void* ptr, std::size_t size) {
  // This could overwrite pre-existing header
  headerBuf_ = folly::IOBuf::copyBuffer(ptr, size);
}

void PipeWriter::setWriterDestination(
    std::shared_ptr<folly::AsyncPipeWriter> pipeWriter) {
  CHECK(pipeWriter) << "Null pipe writer";
  pipe_ = pipeWriter;
}

void PipeWriter::unsetWriterDestination() {
  pipe_.reset();
}
} // namespace katran
