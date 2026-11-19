// Copyright 2004-present Facebook. All Rights Reserved.

#include "katran/kde/api/DirectEncapClientApi.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <fb303/ServiceData.h>

namespace katran_de {

/* Rollout check off: install is skipped, and that counts as success so
 * the sidecar keeps running instead of exiting non-zero. */
TEST(KdeApiRolloutTest, disabledSkipsInstall) {
  KdeInstallParams params{
      .rolloutCheck = [] { return false; }, .iface = "eth0"};
  EXPECT_TRUE(DirectEncapClientApi::installWithParams(params));

  EXPECT_EQ(facebook::fb303::fbData->getCounter("katran_de.client.enabled"), 0);
  // never installed, so the running counter was never published
  EXPECT_FALSE(facebook::fb303::fbData->hasCounter("katran_de.client.running"));
}

/* Rollout check on: install goes ahead. The cgroup does not exist, so
 * it fails before any BPF prog is loaded and the test needs no privileges. */
TEST(KdeApiRolloutTest, enabledAttemptsInstall) {
  KdeInstallParams params{
      .rolloutCheck = [] { return true; },
      .cgroupPath = "/nonexistent",
      .iface = "eth0"};
  EXPECT_FALSE(DirectEncapClientApi::installWithParams(params));

  EXPECT_EQ(facebook::fb303::fbData->getCounter("katran_de.client.enabled"), 1);
  EXPECT_FALSE(facebook::fb303::fbData->hasCounter("katran_de.client.running"));
}

} // namespace katran_de
