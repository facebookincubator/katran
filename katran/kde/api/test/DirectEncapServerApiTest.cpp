// Copyright 2004-present Facebook. All Rights Reserved.

#include "katran/kde/api/DirectEncapServerApi.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <fb303/ServiceData.h>

namespace katran_de {

/* Rollout check off: install is skipped, and that counts as success so
 * the sidecar keeps running instead of exiting non-zero. */
TEST(KdeServerApiRolloutTest, disabledSkipsInstall) {
  KdeInstallParams params{
      .rolloutCheck = [] { return false; }, .iface = "eth0"};
  EXPECT_TRUE(DirectEncapServerApi::installWithParams(params));

  EXPECT_EQ(facebook::fb303::fbData->getCounter("katran_de.server.enabled"), 0);
  // never installed, so the running counter was never published
  EXPECT_FALSE(facebook::fb303::fbData->hasCounter("katran_de.server.running"));
}

/* Rollout check on: install goes ahead. No direct IP is set, so it
 * fails before any BPF prog is loaded and the test needs no privileges. */
TEST(KdeServerApiRolloutTest, enabledAttemptsInstall) {
  KdeInstallParams params{.rolloutCheck = [] { return true; }, .iface = "eth0"};
  EXPECT_FALSE(DirectEncapServerApi::installWithParams(params));

  EXPECT_EQ(facebook::fb303::fbData->getCounter("katran_de.server.enabled"), 1);
  EXPECT_FALSE(facebook::fb303::fbData->hasCounter("katran_de.server.running"));
}

TEST(KdeZonesTest, emptyIsZone1) {
  EXPECT_EQ(katran_tpr::parseZones("", oss_kde_zones), KDE_ZONE_1);
}

TEST(KdeZonesTest, noneAndAll) {
  EXPECT_EQ(katran_tpr::parseZones("none", oss_kde_zones), KDE_ZONE_NONE);
  EXPECT_EQ(katran_tpr::parseZones("all", oss_kde_zones), KDE_ZONE_ALL);
}

TEST(KdeZonesTest, list) {
  EXPECT_EQ(
      katran_tpr::parseZones("zone_1,zone_4", oss_kde_zones),
      KDE_ZONE_1 | KDE_ZONE_4);
}

TEST(KdeZonesTest, invalid) {
  ::testing::FLAGS_gtest_death_test_style =
      "threadsafe"; // otherwise expect death fork fails
  EXPECT_DEATH(
      katran_tpr::parseZones("none,zone_1", oss_kde_zones), "Invalid KDE zone");
  EXPECT_DEATH(
      katran_tpr::parseZones("zone_1,all", oss_kde_zones), "Invalid KDE zone");
  EXPECT_DEATH(
      katran_tpr::parseZones("zone_1,bogus", oss_kde_zones),
      "Invalid KDE zone");
  // names come from the table, so Meta names are unknown to the OSS table
  EXPECT_DEATH(
      katran_tpr::parseZones("origin", oss_kde_zones), "Invalid KDE zone");
}

} // namespace katran_de
