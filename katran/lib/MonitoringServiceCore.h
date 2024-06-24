// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <folly/io/async/AsyncPipe.h>
#include <folly/io/async/DelayedDestruction.h>
#include <folly/io/async/ScopedEventBaseThread.h>
#include "katran/lib/EventPipeCallback.h"
#include "katran/lib/KatranLb.h"
#include "katran/lib/MonitoringStructs.h"

namespace katran {
namespace monitoring {

/**
 * Callback for managing subscription life cycle
 */
class SubscriptionCallback {
 public:
  virtual ~SubscriptionCallback() = default;

  /* Invoked when client cancels subscription */
  virtual void onClientCanceled(ClientId cid) = 0;

  /**
   * Invoked when client successfully subscribed
   * Returns true if the callback succeeds
   */
  virtual bool onClientSubscribed(
      ClientId cid,
      std::shared_ptr<ClientSubscriptionIf> sub,
      const EventIds& subscribed_events) = 0;
};

/**
 * This is the core of the monitoring service, where all the subscription
 * accounting logic lives.
 * To use it, implement both ErrorResultSetterIf and OkResultSetterIf. An rpc
 * service should not inherit this class but use it for composition.
 */
class MonitoringServiceCore
    : public SubscriptionCallback,
      public std::enable_shared_from_this<MonitoringServiceCore> {
 public:
  MonitoringServiceCore() {}

  ~MonitoringServiceCore() override {
    if (initialized_) {
      tearDown();
    }
  }

  /**
   * Helper method for creating a shared ptr with proper deleter
   */
  static std::shared_ptr<MonitoringServiceCore> make() {
    return std::make_shared<MonitoringServiceCore>();
  }

  /**
   * Separate initialization from consturctor to facilitate testing
   * Making it virtual facilitates testing
   */
  virtual bool initialize(std::shared_ptr<KatranMonitor> monitor);

  /**
   * Cleanup routines, e.g. disable events, unset pipe writers, terminate loop.
   */
  virtual void tearDown();

  /**
   * Struct to carry subscription result info
   * @param status The response status
   * @param subscribed_events The set of event successfully subscribed. Being
   * none and that status == OK indicates empty result
   * @param sub_cb The subscription callback used for doing cancellation and
   * rest of accountings
   */
  typedef struct SubscriptionResult {
    ResponseStatus status;
    std::optional<ClientId> cid;
    std::optional<EventIds> subscribed_events;
    std::optional<std::shared_ptr<SubscriptionCallback>> sub_cb;

    /**
     * Constructor used for error and empty results
     */
    explicit SubscriptionResult(ResponseStatus status_in) : status(status_in) {}

    /**
     * Constructor used for successful subscription
     */
    explicit SubscriptionResult(
        ResponseStatus status_in,
        ClientId cid_in,
        EventIds subscribed_events_in,
        std::shared_ptr<SubscriptionCallback> sub_cb_in)
        : status(status_in),
          cid(cid_in),
          subscribed_events(subscribed_events_in),
          sub_cb(sub_cb_in) {}
  } SubscriptionResult;

  /**
   * Try to accept a client subscription.
   * @param requested_events Client requested events
   */
  SubscriptionResult acceptSubscription(const EventIds& requested_events);

  /**
   * SubscriptionCallback method
   * Invoked when client cancels subscription
   */
  void onClientCanceled(ClientId cid) override;

  /**
   * SubscriptionCallback method
   * Invoked when client successfully subscribes
   */
  bool onClientSubscribed(
      ClientId cid,
      std::shared_ptr<ClientSubscriptionIf> sub,
      const EventIds& subscribed_events) override;

  /**
   * Helper getter
   */
  bool initialized() {
    return initialized_;
  }

  /**
   * Change client limit
   * This is NOT thread-safe
   */
  void set_limit(ClientId limit) {
    size_t size = subscription_map_.rlock()->size();
    if (limit >= size) {
      client_limit_ = limit;
    }
  }

  /**
   * Returns true if subscription_map_ contains cid
   */
  bool has_client(ClientId cid) {
    auto subsmap = subscription_map_.rlock();
    return subsmap->find(cid) != subsmap->end();
  }

 protected:
  /**
   * Return the client subscription map for just one event
   */
  ClientSubscriptionMap getSubscriptionMapForEvent(EventId eventId);

  /**
   * Add client subscription to both callback and handler
   */
  bool addSubscription(
      ClientId cid,
      std::shared_ptr<ClientSubscriptionIf> sub,
      const EventIds& subscribed_events);

  /**
   * Remove client subscription from both callback and handler
   */
  void cancelSubscription(ClientId cid);

  /**
   * Flag indicating whether this class is properly initialized
   */
  bool initialized_{false};

  /**
   * Pointer to monitor
   */
  std::shared_ptr<KatranMonitor> monitor_{nullptr};

  /**
   * Map of client id -> ClientSubscriptionIf
   */
  folly::Synchronized<ClientSubscriptionMap> subscription_map_;

  /**
   * A monotonically increasing counter of connected clients, used to generate
   * the next client id
   */
  folly::Synchronized<ClientId> curr_cid_{0};

  /**
   * Limit on the number of monitoring clients (inclusive)
   */
  ClientId client_limit_{kDefaultClientLimit};

  /**
   * Set of monitoring events enabled
   */
  EventIds enabled_events_;

  /**
   * Map of client:set<event>,
   */
  std::unordered_map<ClientId, std::set<EventId>> client_to_event_ids_;

  /**
   * map of readers
   */
  std::unordered_map<EventId, folly::AsyncPipeReader::UniquePtr> readers_;

  /**
   * map of writers
   */
  std::unordered_map<EventId, std::shared_ptr<folly::AsyncPipeWriter>> writers_;

  /**
   * map of pipe callbacks, one per event
   */
  std::unordered_map<EventId, std::unique_ptr<EventPipeCallback>>
      event_pipe_cbs_;

  /**
   * Scoped event base of reader callbacks
   */
  folly::ScopedEventBaseThread reader_thread_;
};

} // namespace monitoring
} // namespace katran
