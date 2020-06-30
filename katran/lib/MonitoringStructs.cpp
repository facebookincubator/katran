// Copyright 2004-present Facebook. All Rights Reserved.

#include "katran/lib/MonitoringStructs.h"

namespace katran {
namespace monitoring {

std::set<EventId> kAllEventIds = {
    EventId::TCP_NONSYN_LRUMISS,
    EventId::PACKET_TOOBIG,
};

std::string toString(const EventId& eventId) {
  switch (eventId) {
    case (EventId::TCP_NONSYN_LRUMISS):
      return "TCP_NONSYN_LRUMISS";
    case (EventId::PACKET_TOOBIG):
      return "PACKET_TOOBIG";
    default:
      return "UNKOWN";
  }
}

std::ostream& operator<<(std::ostream& os, const EventId& eventId) {
  os << toString(eventId);
  return os;
}

} // namespace monitoring
} // namespace katran
