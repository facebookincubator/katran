#pragma once

#include <linux/types.h>
#include <cstddef>
#include <cstdint>

#include "katran/kde/bpf/kde_types.h"

struct kde_zone_map {
  uint8_t bit;
  const char* zone_name;
};

/* Entry i must be zone bit i: stats counters are indexed by that position. */
template <size_t N>
constexpr bool zonesInBitOrder(const kde_zone_map (&zones)[N]) {
  for (size_t i = 0; i < N; i++) {
    if (zones[i].bit != (1 << i)) {
      return false;
    }
  }
  return N <= KDE_MAX_ZONES;
}

inline constexpr kde_zone_map oss_kde_zones[] = {
    {KDE_ZONE_1, "zone_1"},
    {KDE_ZONE_2, "zone_2"},
    {KDE_ZONE_3, "zone_3"},
    {KDE_ZONE_4, "zone_4"},
};
static_assert(zonesInBitOrder(oss_kde_zones), "zone i must be bit i");

constexpr auto KdeSockOpsProgName = "katran_de_so";
constexpr auto KdeTcProgName = "katran_de_tc";
constexpr uint32_t KdeTcFilterPriority = 1715;

constexpr auto KdeSoBssName = "katran_de_so_bss";
constexpr auto KdeTcBssName = "katran_de_tc_bss";
constexpr auto KdeTcLinkName = "katran_de_tc_link";
