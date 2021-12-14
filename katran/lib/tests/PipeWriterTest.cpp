// Copyright 2004-present Facebook. All Rights Reserved.

#include "katran/lib/PipeWriter.h"
#include <fcntl.h>
#include <gtest/gtest.h>

using namespace ::testing;

namespace {
class TestReadCallback : public folly::AsyncReader::ReadCallback {
 public:
  bool isBufferMovable() noexcept override {
    return true;
  }

  void readBufferAvailable(
      std::unique_ptr<folly::IOBuf> readBuf) noexcept override {
    readBuffer_.append(std::move(readBuf));
  }

  void readDataAvailable(size_t len) noexcept override {
    readBuffer_.postallocate(len);
  }

  void getReadBuffer(void** bufReturn, size_t* lenReturn) noexcept override {
    auto res = readBuffer_.preallocate(4000, 65000);
    *bufReturn = res.first;
    *lenReturn = res.second;
  }

  void readEOF() noexcept override {}

  void readErr(const folly::AsyncSocketException&) noexcept override {
    error_ = true;
  }

  std::string getData() {
    auto buf = readBuffer_.move();
    buf->coalesce();
    return std::string((char*)buf->data(), buf->length());
  }

  folly::IOBufQueue readBuffer_{folly::IOBufQueue::cacheChainLength()};
  bool error_{false};
};

class PipeWriterTest : public Test {
 public:
  void SetUp() override {
    int rc = pipe2(pipeFds_, O_NONBLOCK);
    EXPECT_EQ(rc, 0);
    reader_ = folly::AsyncPipeReader::newReader(
        &evb_, folly::NetworkSocket::fromFd(pipeFds_[0]));
    auto writer = folly::AsyncPipeWriter::newWriter(
        &evb_, folly::NetworkSocket::fromFd(pipeFds_[1]));
    writer_ = std::move(writer);
  }

 protected:
  folly::EventBase evb_;
  int pipeFds_[2];
  folly::AsyncPipeReader::UniquePtr reader_{nullptr};
  std::shared_ptr<folly::AsyncPipeWriter> writer_{nullptr};
  TestReadCallback readCallback_;
};

} // namespace

TEST_F(PipeWriterTest, SimpleWrite) {
  katran::PipeWriter pipeWriter;
  std::string buf = "ramen";
  reader_->setReadCB(&readCallback_);
  pipeWriter.setWriterDestination(writer_);
  pipeWriter.writeData(buf.c_str(), buf.size());
  evb_.loopOnce();
  pipeWriter.stop();
  EXPECT_EQ(readCallback_.getData(), "ramen");
  EXPECT_FALSE(readCallback_.error_);
  EXPECT_EQ(pipeWriter.getWrites(), 1);
  EXPECT_EQ(pipeWriter.getErrs(), 0);
}

TEST_F(PipeWriterTest, WriteAfterStop) {
  katran::PipeWriter pipeWriter;
  std::string buf = "ramen";
  reader_->setReadCB(&readCallback_);
  pipeWriter.setWriterDestination(writer_);
  pipeWriter.writeData(buf.c_str(), buf.size());
  pipeWriter.stop();
  pipeWriter.writeData(buf.c_str(), buf.size());
  evb_.loopOnce();
  EXPECT_EQ(readCallback_.getData(), "ramen");
  EXPECT_FALSE(readCallback_.error_);
  EXPECT_EQ(pipeWriter.getWrites(), 1);
  EXPECT_EQ(pipeWriter.getErrs(), 0);
}
