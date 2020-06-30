// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <folly/Format.h>
#include <folly/Utility.h>
#include <folly/io/Cursor.h>
#include <folly/io/async/AsyncPipe.h>
#include <folly/io/async/AsyncSocketException.h>
#include "katran/lib/KatranLbStructs.h"
#include "katran/lib/KatranMonitor.h"
#include "katran/lib/MonitoringStructs.h"

namespace katran {
namespace monitoring {

namespace {
constexpr uint32_t kReadBufSize = 4000;
constexpr uint32_t kReadBufAllocSize = 4096;
} // namespace

class EventPipeCallback : public folly::AsyncReader::ReadCallback {
 public:
  EventPipeCallback() = delete;
  explicit EventPipeCallback(EventId event_id) : event_id_(event_id) {}

  /**
   * This facilitates testing
   */
  explicit EventPipeCallback(
      EventId event_id,
      folly::Synchronized<ClientSubscriptionMap>&& subsmap)
      : cb_subsmap_(std::move(subsmap)), event_id_(event_id) {}

  /**
   * Always use `readDataAvailable` instead of `readBufferAvailable`
   */
  bool isBufferMovable() noexcept override {
    return false;
  }

  /**
   * Invoked when buffer is available to read
   * Should not be called since isBufferMovable always returns false
   */
  void readBufferAvailable(
      std::unique_ptr<folly::IOBuf> readBuf) noexcept override {
    logerror("getBufferAvailable called while buffer is not movable");
    readBuffer(std::move(readBuf));
  }

  /**
   * Construct read buffer
   */
  void getReadBuffer(void** bufReturn, size_t* lenReturn) noexcept override {
    auto res = readBuffer_.preallocate(kReadBufSize, kReadBufAllocSize);
    *bufReturn = res.first;
    *lenReturn = res.second;
  }

  /**
   * Called when data is available to read
   * Pass the entire buf to readBuffer, which will properly handle incomplete
   * messages and "leftover"
   */
  void readDataAvailable(size_t len) noexcept override {
    readBuffer_.postallocate(len);
    auto buf = readBuffer_.move();
    buf->coalesce();
    readBuffer(std::move(buf));
  }

  /**
   * When the event is no longer under monitoring, it's "closed",
   * and there's nothing we should do.
   * Otherwise something is wrong and report error
   */
  void readEOF() noexcept override {
    // Require event_closed to be set before telling monitor to stop monitoring
    if (enabled()) {
      logerror("EOF read while event not closed");
    }
  }

  void readErr(const folly::AsyncSocketException& e) noexcept override {
    logerror(e.what());
  }

  /**
   * Actual read buffer implementation
   */
  void readBuffer(std::unique_ptr<folly::IOBuf>&& buf) noexcept;

  void logerror(std::string msg) {
    LOG(ERROR) << folly::format(
        "EventPipeCallback({}): {}", toString(event_id_), msg);
  }

  /**
   * Enable the callback
   */
  void enable() {
    *(event_enabled_.wlock()) = true;
  }

  /**
   * return true if the callback is enabled
   */
  bool enabled() {
    return *(event_enabled_.rlock());
  }

  /**
   * Disable the callback
   */
  void disable() {
    *(event_enabled_.wlock()) = false;
  }

  /**
   * Add a new client subscription
   */
  void addClientSubscription(
      std::pair<ClientId, std::shared_ptr<ClientSubscriptionIf>>&& newSub);

  /**
   * Remove susbcription by client id
   */
  void removeClientSubscription(ClientId cid);

 private:
  /**
   * A buffer queue in case readDataAvailable is chosen. Although it is not
   * supposed to happen, having a fallback buffer here avoids potential segfault
   * when bufReturn is nullptr.
   */
  folly::IOBufQueue readBuffer_;

  /**
   * A ClientId -> ClientSubscription map, where all the clients have
   * subscribed to the event to which this callback is attached.
   */
  folly::Synchronized<ClientSubscriptionMap> cb_subsmap_;

  /**
   * A flag indicating whether the event is enabled.
   */
  folly::Synchronized<bool> event_enabled_{false};

  /**
   * The event to which this callback is attached.
   */
  EventId event_id_;
};

} // namespace monitoring
} // namespace katran
