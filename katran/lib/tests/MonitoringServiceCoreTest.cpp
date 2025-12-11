// Copyright 2004-present Facebook. All Rights Reserved.

#include "katran/lib/MonitoringServiceCore.h"
#include <fcntl.h>
#include <folly/Random.h>
#include <gtest/gtest.h>
#include <algorithm>
#include <functional>
#include <mutex>

using namespace ::testing;
using namespace ::katran;
using namespace ::katran::monitoring;

namespace {
const std::set<EventId> kEventIds = {
    EventId::TCP_NONSYN_LRUMISS,
    EventId::PACKET_TOOBIG,
};
} // namespace

class MockMonitoringServiceCore : public MonitoringServiceCore {
 public:
  MockMonitoringServiceCore() {}

  static std::shared_ptr<MockMonitoringServiceCore> make() {
    return std::make_shared<MockMonitoringServiceCore>();
  }

  bool initialize(std::shared_ptr<KatranMonitor> /* unused */) override {
    for (const auto& eventId : kEventIds) {
      int pipeFds[2];
      int rc = pipe2(pipeFds, O_NONBLOCK);
      EXPECT_EQ(rc, 0);
      auto reader = folly::AsyncPipeReader::newReader(
          reader_thread_.getEventBase(),
          folly::NetworkSocket::fromFd(pipeFds[0]));
      auto writer = folly::AsyncPipeWriter::newWriter(
          reader_thread_.getEventBase(),
          folly::NetworkSocket::fromFd(pipeFds[1]));
      auto cb = std::make_unique<EventPipeCallback>(eventId);
      cb->enable();
      reader->setReadCB(cb.get());
      readers_.insert({eventId, std::move(reader)});
      event_pipe_cbs_.insert({eventId, std::move(cb)});
      my_writers_.insert({eventId, std::move(writer)});
      enabled_events_.insert(eventId);
    }
    initialized_ = true;
    return true;
  }

 private:
  std::unordered_map<
      EventId,
      std::unique_ptr<
          folly::AsyncPipeWriter,
          folly::DelayedDestruction::Destructor>>
      my_writers_;
};

class MockClientSubscription : public ClientSubscriptionIf {
 public:
  void sendEvent(const Event& event) override {
    sent_events_.push_back(event);
  }

  bool hasEvent(const EventId& eventId) override {
    return std::find_if(
               sent_events_.begin(),
               sent_events_.end(),
               [=](const auto& it) -> bool { return it.id == eventId; }) !=
        sent_events_.end();
  }

  std::vector<Event> sent_events_;
};

class TestMonitoringServiceCore : public Test {
 public:
  void SetUp() override {
    core = MockMonitoringServiceCore::make();
    EXPECT_TRUE(core->initialize(nullptr));
  }
  std::shared_ptr<MockMonitoringServiceCore> core{nullptr};
};

TEST_F(TestMonitoringServiceCore, SimpleAcceptSubscription) {
  EventIds eventIds = {
      EventId::TCP_NONSYN_LRUMISS,
  };
  auto res = core->acceptSubscription(eventIds);
  EXPECT_EQ(res.status, ResponseStatus::OK);
}

TEST_F(TestMonitoringServiceCore, SimpleErrors) {
  EventIds eventIds = {
      EventId::UNKNOWN,
  };
  auto res = core->acceptSubscription(eventIds);
  EXPECT_EQ(res.status, ResponseStatus::NOT_SUPPORTED);

  EventIds emptyEventIds = {};
  auto res2 = core->acceptSubscription(emptyEventIds);
  EXPECT_EQ(res2.status, ResponseStatus::OK);
  EXPECT_FALSE(res2.subscribed_events.has_value());

  core->set_limit(0);
  EventIds goodEventIds = {
      EventId::PACKET_TOOBIG,
  };
  auto res3 = core->acceptSubscription(goodEventIds);
  EXPECT_EQ(res3.status, ResponseStatus::TOOMANY_CLIENTS);
}

TEST_F(TestMonitoringServiceCore, EventIntersection) {
  EventIds eventIds = {
      EventId::UNKNOWN,
      EventId::TCP_NONSYN_LRUMISS,
  };
  EventIds expectEventIds = {
      EventId::TCP_NONSYN_LRUMISS,
  };

  auto res = core->acceptSubscription(eventIds);
  EXPECT_EQ(res.status, ResponseStatus::OK);
  EXPECT_TRUE(res.subscribed_events.has_value());
  EXPECT_EQ(res.subscribed_events.value(), expectEventIds);
}

TEST_F(TestMonitoringServiceCore, RacingClients) {
  EventIds group1EventIds = {
      EventId::TCP_NONSYN_LRUMISS,
  };
  EventIds group2EventIds = {
      EventId::PACKET_TOOBIG,
  };
  std::vector<std::thread> threads;
  folly::Synchronized<std::vector<uint32_t>> cids;
  for (int i = 0; i < 30; i++) {
    threads.emplace_back([&]() mutable {
      ClientId cid;
      if (folly::Random::rand32() % 2 == 0) {
        auto res = core->acceptSubscription(group1EventIds);
        EXPECT_EQ(res.status, ResponseStatus::OK);
        EXPECT_TRUE(res.subscribed_events.has_value());
        EXPECT_EQ(res.subscribed_events.value(), group1EventIds);
        EXPECT_TRUE(res.cid.has_value());
        cid = *res.cid;
      } else {
        auto res = core->acceptSubscription(group2EventIds);
        EXPECT_EQ(res.status, ResponseStatus::OK);
        EXPECT_TRUE(res.subscribed_events.has_value());
        EXPECT_EQ(res.subscribed_events.value(), group2EventIds);
        EXPECT_TRUE(res.cid.has_value());
        cid = *res.cid;
      }
      auto cids_ = cids.wlock();
      cids_->push_back(cid);
    });
  }
  for (int i = 0; i < 30; i++) {
    threads[i].join();
  }
  cids.withWLock([](auto& client_ids) {
    EXPECT_EQ(client_ids.size(), 30);
    std::sort(client_ids.begin(), client_ids.end(), std::less<uint32_t>());
    for (int i = 0; i < 30; i++) {
      EXPECT_EQ(client_ids[i], i);
    }
  });
}

TEST_F(TestMonitoringServiceCore, SubscribeAndCancel) {
  EventIds eventIds = {
      EventId::TCP_NONSYN_LRUMISS,
  };
  auto submock = std::make_shared<MockClientSubscription>();
  auto res = core->acceptSubscription(eventIds);
  EXPECT_EQ(res.status, ResponseStatus::OK);
  EXPECT_TRUE(res.cid.has_value());
  EXPECT_TRUE(res.sub_cb.has_value());
  EXPECT_TRUE(res.subscribed_events.has_value());
  EXPECT_EQ(res.subscribed_events.value().size(), 1);

  auto cid = *res.cid;
  EXPECT_TRUE(res.sub_cb.value()->onClientSubscribed(
      *res.cid, submock, *res.subscribed_events));
  EXPECT_TRUE(core->has_client(cid));
  res.sub_cb.value()->onClientCanceled(cid);
  EXPECT_FALSE(core->has_client(cid));
}
