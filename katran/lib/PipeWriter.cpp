// Copyright 2004-present Facebook. All Rights Reserved.

#include <unistd.h>
#include <cstring>
#include <folly/io/IOBuf.h>
#include "katran/lib/PipeWriter.h"

namespace katran {
  PipeWriter::PipeWriter() {}

  void PipeWriter::writeData(const void *ptr, std::size_t size) {
    VLOG_EVERY_N(4, 10) << __func__ << " write " << size << " bytes";

    if (size == 0) {
      LOG(ERROR) << "Zero-sized data. Skipping";
      return;
    }

    if (!enabled_) {
      VLOG_EVERY_N(4, 10) << "Disabled pipe writer. Skipping";
      return;
    }

    if (auto pipe = pipe_.lock()) {
      pipe->write(&writeCallback_, ptr, size);
    } else  {
      LOG(ERROR) << __func__ << " Can't lock pipe";
    }
  }

  void PipeWriter::writeHeader(const void *ptr, std::size_t size) {
    // This could overwrite pre-existing header
    headerBuf_ = folly::IOBuf::copyBuffer(ptr, size);
  }

  void PipeWriter::setWriterDestination(std::weak_ptr<folly::AsyncPipeWriter> pipeWriter) {
    pipe_ = pipeWriter;
  }

  void PipeWriter::unsetWriterDestination() {
    if (auto pipe = pipe_.lock()) {
      pipe->closeOnEmpty();
    }
    pipe_.reset();
  }
} // namespace katran
