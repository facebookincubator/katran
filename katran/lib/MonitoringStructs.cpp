// Copyright 2004-present Facebook. All Rights Reserved.

#include "katran/lib/MonitoringStructs.h"

namespace katran {


std::set<MonitoringEventId> kAllEventIds = {
    MonitoringEventId::TCP_NONSYN_LRUMISS,
    MonitoringEventId::PACKET_TOOBIG,
};

std::string toString(const MonitoringEventId& eventId) {
  switch (eventId) {
    case (MonitoringEventId::TCP_NONSYN_LRUMISS):
      return "TCP_NONSYN_LRUMISS";
    case (MonitoringEventId::PACKET_TOOBIG):
      return "PACKET_TOOBIG";
    default:
      return "UNKOWN";
  }
}

std::ostream& operator<<(
    std::ostream& os,
    const MonitoringEventId& eventId) {
  os << toString(eventId);
  return os;
}

} // namespace katran
