// Copyright 2004-present Facebook. All Rights Reserved.

#include "katran/lib/EventPipeCallback.h"
#include <fcntl.h>
#include <folly/io/async/EventBase.h>
#include <gtest/gtest.h>
#include <chrono>
#include <vector>
#include "katran/lib/PcapStructs.h"

using namespace ::testing;
using namespace ::katran;
using namespace ::katran::monitoring;

namespace {
// 100 bytes
std::string kDefaultRaw =
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Cras at sem nec tortor aliquet ullamcorper.";
} // namespace

class MockClientSubscription : public ClientSubscriptionIf {
 public:
  explicit MockClientSubscription() {}
  void sendEvent(const Event& event) override {
    sent_events_.push_back(std::move(event));
  }

  bool hasEvent(const EventId& eventId) override {
    for (const auto& event : sent_events_) {
      if (event.id == eventId) {
        return true;
      }
    }
    return false;
  }

  std::vector<Event> sent_events_;
};

class EventPipeCallbackTest : public Test {
 public:
  void SetUp() override {
    int rc = pipe2(pipeFds_, O_NONBLOCK);
    EXPECT_EQ(rc, 0);
    reader_ = folly::AsyncPipeReader::newReader(
        &evb_, folly::NetworkSocket::fromFd(pipeFds_[0]));
    writer_ = folly::AsyncPipeWriter::newWriter(
        &evb_, folly::NetworkSocket::fromFd(pipeFds_[1]));
  }

  pcaprec_hdr_s getDefaultPcapRecordHeader() {
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
    rec_hdr.incl_len = 100;
    rec_hdr.orig_len = 200;
    return rec_hdr;
  }

  std::string getDefaultEventData(pcaprec_hdr_s rec_hdr) {
    folly::StringPiece s(kDefaultRaw);
    auto hdr_buf = folly::IOBuf::copyBuffer(&rec_hdr, sizeof(rec_hdr));
    auto raw_buf =
        folly::IOBuf::copyBuffer(kDefaultRaw.c_str(), kDefaultRaw.size());
    hdr_buf->appendChain(std::move(raw_buf));
    hdr_buf->coalesce();
    return std::string(
        reinterpret_cast<const char*>(hdr_buf->data()), hdr_buf->length());
  }

  folly::EventBase evb_;
  int pipeFds_[2];
  folly::AsyncPipeReader::UniquePtr reader_{nullptr};
  folly::AsyncPipeWriter::UniquePtr writer_{nullptr};
  std::unique_ptr<EventPipeCallback> eventPipeCb_{nullptr};
};

TEST_F(EventPipeCallbackTest, SimpleCallbackTest) {
  // Preparation
  auto mockSubscription = std::make_shared<MockClientSubscription>();
  auto rechdr = getDefaultPcapRecordHeader();
  std::string event_data = getDefaultEventData(rechdr);
  Event expect_event;
  expect_event.id = EventId::TCP_NONSYN_LRUMISS;
  expect_event.pktsize = 200;
  expect_event.data = event_data;

  ClientSubscriptionMap subsmap;
  for (int i = 1; i <= 10; i++) {
    subsmap.insert({i, mockSubscription});
  }
  eventPipeCb_ = std::make_unique<EventPipeCallback>(
      EventId::TCP_NONSYN_LRUMISS,
      folly::Synchronized<ClientSubscriptionMap>(std::move(subsmap)));
  eventPipeCb_->enable();
  reader_->setReadCB(eventPipeCb_.get());

  writer_->write(nullptr, &rechdr, sizeof(rechdr));
  writer_->write(nullptr, kDefaultRaw.c_str(), kDefaultRaw.size());
  writer_->closeOnEmpty();
  // Just in case one loop isn't enough.
  evb_.loop();
  evb_.loop();

  EXPECT_EQ(mockSubscription->sent_events_.size(), 10);
  for (int i = 0; i < 10; i++) {
    auto sent_event = mockSubscription->sent_events_[i];
    EXPECT_EQ(expect_event.id, sent_event.id);
    EXPECT_EQ(expect_event.pktsize, sent_event.pktsize);
    EXPECT_EQ(expect_event.data, sent_event.data);
  }
}
