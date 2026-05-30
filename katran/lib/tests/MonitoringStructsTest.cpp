// (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.

#include <gtest/gtest.h>
#include <sstream>

#include "katran/lib/MonitoringStructs.h"

namespace katran {
namespace monitoring {

TEST(MonitoringStructsTest, ToStringKnownEvents) {
  EXPECT_EQ(toString(EventId::TCP_NONSYN_LRUMISS), "TCP_NONSYN_LRUMISS");
  EXPECT_EQ(toString(EventId::PACKET_TOOBIG), "PACKET_TOOBIG");
  EXPECT_EQ(
      toString(EventId::QUIC_PACKET_DROP_NO_REAL), "QUIC_PACKET_DROP_NO_REAL");
}

TEST(MonitoringStructsTest, ToStringUnknownEventReturnsUnknown) {
  // UNKNOWN (255) and any other unrecognized cast should return "UNKNOWN".
  EXPECT_EQ(toString(EventId::UNKNOWN), "UNKNOWN");
  EXPECT_EQ(toString(static_cast<EventId>(100)), "UNKNOWN");
}

TEST(MonitoringStructsTest, StreamOperatorMatchesToString) {
  for (const EventId id : kAllEventIds) {
    std::ostringstream oss;
    oss << id;
    EXPECT_EQ(oss.str(), toString(id));
  }
}

TEST(MonitoringStructsTest, AllEventIdsContainsExactlyThreeKnownEvents) {
  const std::set<EventId> expected = {
      EventId::TCP_NONSYN_LRUMISS,
      EventId::PACKET_TOOBIG,
      EventId::QUIC_PACKET_DROP_NO_REAL,
  };
  EXPECT_EQ(kAllEventIds, expected);
}

TEST(MonitoringStructsTest, AllEventIdsDoesNotContainUnknown) {
  EXPECT_EQ(kAllEventIds.count(EventId::UNKNOWN), 0u);
}

} // namespace monitoring
} // namespace katran
