// Copyright 2004-present Facebook. All Rights Reserved.
#include "katran/lib/MonitoringServiceCore.h"
#include <fcntl.h>
#include <fmt/core.h>

namespace katran {
namespace monitoring {

// Be less verbose
using SubscriptionResult = MonitoringServiceCore::SubscriptionResult;

bool MonitoringServiceCore::initialize(std::shared_ptr<KatranMonitor> monitor) {
  if (initialized_) {
    return true;
  }
  if (monitor == nullptr) {
    LOG(ERROR) << "Null monitor";
    return false;
  }
  monitor_ = monitor;
  // Get all the events that this monitor supports
  auto eventIds = monitor_->getWriterEnabledEvents();

  // For each event, get its writ in ker, set up pipes and callbacks
  for (const auto& eventId : eventIds) {
    int pipeFds[2];
    int rc = pipe2(pipeFds, O_NONBLOCK);
    if (rc != 0) {
      LOG(ERROR) << fmt::format(
          "Creating pipes for event {} failed: {}", toString(eventId), rc);
      continue;
    }
    auto reader = folly::AsyncPipeReader::newReader(
        reader_thread_.getEventBase(),
        folly::NetworkSocket::fromFd(pipeFds[0]));
    auto writer = folly::AsyncPipeWriter::newWriter(
        reader_thread_.getEventBase(),
        folly::NetworkSocket::fromFd(pipeFds[1]));

    // Create callback object
    auto cb = std::make_unique<EventPipeCallback>(eventId);
    cb->enable();
    reader->setReadCB(cb.get());
    readers_.insert({eventId, std::move(reader)});
    event_pipe_cbs_.insert({eventId, std::move(cb)});

    // We want the monitor to hold a weak pointer to the writer, because
    // we don't know if this handler along with the reader event base are
    // going to be destroyed before/after katran monitor. If this handler and
    // its reader event base gets destroyed prior to katran monitor, when
    // katran monitor gets destroyed later, we don't want this AsyncPipeWriter
    // to invoke its dtor coz it will try to reference the reader event base
    // and will cause segfault.
    // TODO: deprecate weak_ptr
    std::shared_ptr<folly::AsyncPipeWriter> shared_writer = std::move(writer);
    writers_.insert({eventId, shared_writer});
    monitor_->setAsyncPipeWriter(eventId, shared_writer);

    // This event is properly set up, add it
    enabled_events_.insert(eventId);
  }

  initialized_ = true;
  return true;
}

void MonitoringServiceCore::tearDown() {
  if (initialized_) {
    for (auto& eventAndCb : event_pipe_cbs_) {
      eventAndCb.second->disable();
    }
    // This facilitate testing
    if (monitor_) {
      for (auto eventId : enabled_events_) {
        monitor_->unsetAsyncPipeWriter(eventId);
      }
    }
  }
}

SubscriptionResult MonitoringServiceCore::acceptSubscription(
    const EventIds& requested_events) {
  CHECK(initialized_);
  ClientId new_cid;
  EventIds subscribed_events;

  if (enabled_events_.size() == 0) {
    // Handler supports no events
    LOG(ERROR) << "Received requests but handler supports no events";
    return SubscriptionResult(ResponseStatus::NOT_SUPPORTED);
  }

  if (requested_events.size() == 0) {
    // Why send requests in the first place?
    LOG(INFO) << "Received requests with no events";
    return SubscriptionResult(ResponseStatus::OK);
  }

  // Check if we have too many clients
  {
    auto num_client = subscription_map_.rlock()->size();
    if (num_client >= client_limit_) {
      LOG(INFO) << "Rejecting request: Too may clients";
      return SubscriptionResult(ResponseStatus::TOOMANY_CLIENTS);
    }
  }

  // Compute the set of events that client gets subscribed to
  std::set_intersection(
      enabled_events_.begin(),
      enabled_events_.end(),
      requested_events.begin(),
      requested_events.end(),
      std::inserter(subscribed_events, subscribed_events.end()));
  if (subscribed_events.size() == 0) {
    LOG(INFO) << "Rejecting request: None of client's events are supported";
    return SubscriptionResult(ResponseStatus::NOT_SUPPORTED);
  }

  // Assign client id
  {
    auto new_cid_ptr = curr_cid_.wlock();
    new_cid = (*new_cid_ptr)++;
  }

  // At this point we've found a valid set of events,
  // thus response result should be Ok
  return SubscriptionResult(
      ResponseStatus::OK,
      new_cid,
      subscribed_events, // copy since it's on the stack
      std::dynamic_pointer_cast<SubscriptionCallback>(shared_from_this()));
}

void MonitoringServiceCore::onClientCanceled(ClientId cid) {
  cancelSubscription(cid);
}

bool MonitoringServiceCore::onClientSubscribed(
    ClientId cid,
    std::shared_ptr<ClientSubscriptionIf> sub,
    const EventIds& subscribed_events) {
  return addSubscription(cid, sub, subscribed_events);
}

ClientSubscriptionMap MonitoringServiceCore::getSubscriptionMapForEvent(
    EventId eventId) {
  CHECK(initialized_);
  ClientSubscriptionMap map;
  auto subsmap = subscription_map_.rlock();
  for (const auto& it : *subsmap) {
    auto clientAndEventIds = client_to_event_ids_.find(it.first);
    if (clientAndEventIds != client_to_event_ids_.end() &&
        clientAndEventIds->second.find(eventId) !=
            clientAndEventIds->second.end()) {
      map.insert({it.first, it.second});
    }
  }
  return map;
}

bool MonitoringServiceCore::addSubscription(
    ClientId cid,
    std::shared_ptr<ClientSubscriptionIf> sub,
    const EventIds& subscribed_events) {
  // Store another shared ptr of subscription at the corresponding
  // event pipe callbacks so that future events can be sent to this client.
  // To avoid partial progress, put valid callback in a vector and insert
  // subscription in a single batch
  CHECK(initialized_);
  std::vector<EventPipeCallback*> cbs;
  for (const auto& eventId : subscribed_events) {
    auto cb = event_pipe_cbs_.find(eventId);
    if (cb == event_pipe_cbs_.end()) {
      LOG(ERROR) << "Cannot find read callback for event " << eventId;
      return false;
    }
    cbs.push_back(cb->second.get());
  }
  for (auto& cb : cbs) {
    cb->addClientSubscription({cid, sub});
  }
  auto subsmap = subscription_map_.wlock();
  subsmap->insert({cid, sub});
  client_to_event_ids_.insert({cid, subscribed_events});
  return true;
}

void MonitoringServiceCore::cancelSubscription(ClientId cid) {
  // client cancellation callback
  // Remove subscription from all pipe event callbacks
  CHECK(initialized_);
  auto clientAndEventIds = client_to_event_ids_.find(cid);
  if (clientAndEventIds == client_to_event_ids_.end()) {
    LOG(ERROR) << fmt::format("client {} has no associated events", cid);
    // Best effor to clean up associated data
    for (auto& eventAndCallback : event_pipe_cbs_) {
      eventAndCallback.second->removeClientSubscription(cid);
    }
  } else {
    for (const auto& eventId : clientAndEventIds->second) {
      auto eventAndCallback = event_pipe_cbs_.find(eventId);
      CHECK(eventAndCallback != event_pipe_cbs_.end());
      eventAndCallback->second->removeClientSubscription(
          clientAndEventIds->first);
    }
  }
  // Remove client from subscriptio map
  auto subsmap = subscription_map_.wlock();
  subsmap->erase(cid);
}

} // namespace monitoring
} // namespace katran
