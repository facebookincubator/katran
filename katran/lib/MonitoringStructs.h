// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <ostream>
#include <string>
#include <set>

namespace katran {

// This is the internal enum for event id. Protocol specific types will need to
// be casted to/from this type. One can take advantage of the UNKNOWN event id
// for handling casting exception.
enum class MonitoringEventId : uint8_t{
  TCP_NONSYN_LRUMISS = 0,
  PACKET_TOOBIG = 1,
  UNKNOWN = 255,
};

// A set of all valid events
extern std::set<MonitoringEventId> kAllEventIds;

// Helper function converting event to string
std::string toString(const MonitoringEventId& eventId);

// Helper operator definition that makes logging easier
std::ostream& operator<<(
    std::ostream& os,
    const MonitoringEventId& eventId);

} // namespace katran
