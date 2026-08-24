// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once
#include <memory>
#include <ostream>
#include <set>
#include <string>
#include <unordered_map>

namespace katran {
namespace monitoring {

constexpr auto kDefaultClientLimit = 10;

// This is the internal enum for event id. Protocol specific types will need
// to be converted to/from this type via eventIdFromRaw() below (do not
// static_cast raw values directly -- that can produce an out-of-range enum
// value). Use the UNKNOWN event id to represent an unrecognized value.
enum class EventId : uint8_t {
  TCP_NONSYN_LRUMISS = 0,
  PACKET_TOOBIG = 1,
  QUIC_PACKET_DROP_NO_REAL = 2,
  UNKNOWN = 255,
};

// A set of all valid events
extern std::set<EventId> kAllEventIds;

// Enum of response status
enum ResponseStatus {
  OK = 0,
  NOT_SUPPORTED = 1,
  TOOMANY_CLIENTS = 2,
  INTERNAL_ERROR = 3,
};

// Helper function converting event to string
std::string toString(const EventId& eventId);

// Helper function converting a raw event id (e.g. received over the wire)
// to the associated EventId. Returns EventId::UNKNOWN for any value that
// does not match one of the named enumerators above, so callers never need
// to (unsafely) static_cast a raw value into this enum themselves. Kept
// alongside the enum definition so it is updated whenever EventId is.
EventId eventIdFromRaw(uint32_t rawEventId);

// Helper operator definition that makes logging easier
std::ostream& operator<<(std::ostream& os, const EventId& eventId);

struct Event {
  EventId id;
  uint32_t pktsize;
  std::string data;
};

using ClientId = uint32_t;
using EventIds = std::set<EventId>;

/**
 * A helper class to store both subscribed events and publisher
 */
class ClientSubscriptionIf {
 public:
  virtual ~ClientSubscriptionIf() = default;
  /**
   * Stream event to client.
   */
  virtual void sendEvent(const Event& event) = 0;

  /**
   * Return true if this subscription contains the event
   */
  virtual bool hasEvent(const EventId& event_id) = 0;
};

using ClientSubscriptionMap =
    std::unordered_map<ClientId, std::shared_ptr<ClientSubscriptionIf>>;

} // namespace monitoring
} // namespace katran
