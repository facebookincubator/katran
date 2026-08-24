// Copyright 2004-present Facebook. All Rights Reserved.

#include "katran/lib/MonitoringStructs.h"

#include <fmt/core.h>
#include <glog/logging.h>

namespace katran {
namespace monitoring {

std::set<EventId> kAllEventIds = {
    EventId::TCP_NONSYN_LRUMISS,
    EventId::PACKET_TOOBIG,
    EventId::QUIC_PACKET_DROP_NO_REAL,
};

std::string toString(const EventId& eventId) {
  switch (eventId) {
    case (EventId::TCP_NONSYN_LRUMISS):
      return "TCP_NONSYN_LRUMISS";
    case (EventId::PACKET_TOOBIG):
      return "PACKET_TOOBIG";
    case (EventId::QUIC_PACKET_DROP_NO_REAL):
      return "QUIC_PACKET_DROP_NO_REAL";
    default:
      return "UNKNOWN";
  }
}

std::ostream& operator<<(std::ostream& os, const EventId& eventId) {
  os << toString(eventId);
  return os;
}

EventId eventIdFromRaw(uint32_t rawEventId) {
  switch (rawEventId) {
    case static_cast<uint32_t>(EventId::TCP_NONSYN_LRUMISS):
      return EventId::TCP_NONSYN_LRUMISS;
    case static_cast<uint32_t>(EventId::PACKET_TOOBIG):
      return EventId::PACKET_TOOBIG;
    case static_cast<uint32_t>(EventId::QUIC_PACKET_DROP_NO_REAL):
      return EventId::QUIC_PACKET_DROP_NO_REAL;
    case static_cast<uint32_t>(EventId::UNKNOWN):
      return EventId::UNKNOWN;
    default:
      LOG(ERROR) << fmt::format("invalid event id {}", rawEventId);
      return EventId::UNKNOWN;
  }
}

} // namespace monitoring
} // namespace katran
