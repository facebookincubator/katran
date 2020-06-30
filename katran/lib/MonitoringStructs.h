// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <ostream>
#include <set>
#include <string>

namespace katran {
namespace monitoring {

// This is the internal enum for event id. Protocol specific types will need to
// be casted to/from this type. One can take advantage of the UNKNOWN event id
// for handling casting exception.
enum class EventId : uint8_t {
  TCP_NONSYN_LRUMISS = 0,
  PACKET_TOOBIG = 1,
  UNKNOWN = 255,
};

// A set of all valid events
extern std::set<EventId> kAllEventIds;

// Helper function converting event to string
std::string toString(const EventId& eventId);

// Helper operator definition that makes logging easier
std::ostream& operator<<(std::ostream& os, const EventId& eventId);

} // namespace monitoring
} // namespace katran
