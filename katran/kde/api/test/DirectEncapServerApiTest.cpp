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

/* Zone parsing used to be reached through the gflags; both CLIs and the API
 * call the parser directly now, so test it directly too. */
TEST(ServerKdeZonesTest, default_zone) {
  EXPECT_EQ(
      katran_tpr::ServerDirectEncap::parseServerZonesList("origin"),
      KDE_ZONE_ORIGIN);
}

TEST(ServerKdeZonesTest, zone_all) {
  EXPECT_EQ(
      katran_tpr::ServerDirectEncap::parseServerZonesList("all"), KDE_ZONE_ALL);
}

TEST(ServerKdeZonesTest, zone_edge_origin) {
  EXPECT_EQ(
      katran_tpr::ServerDirectEncap::parseServerZonesList("origin,edge"),
      KDE_ZONE_ORIGIN | KDE_ZONE_EDGE);
}

TEST(ServerKdeZonesTest, zone_cloud_cw) {
  EXPECT_EQ(
      katran_tpr::ServerDirectEncap::parseServerZonesList("cloud_cw"),
      KDE_ZONE_CLOUD_CW);
}

TEST(ServerKdeZonesTest, zone_cloud_cw_with_origin) {
  EXPECT_EQ(
      katran_tpr::ServerDirectEncap::parseServerZonesList("origin,cloud_cw"),
      KDE_ZONE_ORIGIN | KDE_ZONE_CLOUD_CW);
}

TEST(ServerKdeZonesTest, invalidZone) {
  ::testing::FLAGS_gtest_death_test_style =
      "threadsafe"; // otherwise expect death fork fails
  EXPECT_DEATH(
      {
        katran_tpr::ServerDirectEncap::parseServerZonesList(
            "origin,invalid_zone,edge");
      },
      "Invalid kde zone");
}

} // namespace katran_de
