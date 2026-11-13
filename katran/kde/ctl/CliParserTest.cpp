// (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.

#include <optional>

#include <folly/portability/GTest.h>

#include "katran/kde/ctl/CliParser.h"

namespace katran_de::ctl {
namespace {

std::optional<InstallArgs> testInstallArgs;

void installArgs(const InstallArgs& args) {
  testInstallArgs = args;
}

void ignoreClean(const CleanArgs&) {}

void ignoreStats(const StatsArgs&, bool) {}

void ignorePing(const PingArgs&) {}

/* --direct-ip tests */
TEST(CliParserTest, DirectIpIsParsed) {
  testInstallArgs.reset();
  auto app = CliParser::genCliApp(
      installArgs, ignoreClean, ignoreStats, DirectEncapMode::SERVER);
  app->parse("run --direct-ip=c0de::1");
  ASSERT_TRUE(testInstallArgs.has_value());
  EXPECT_EQ(testInstallArgs->directIp, "c0de::1");
}

TEST(CliParserTest, DirectIpIsRequiredForServer) {
  testInstallArgs.reset();
  auto app = CliParser::genCliApp(
      installArgs, ignoreClean, ignoreStats, DirectEncapMode::SERVER);
  EXPECT_THROW(app->parse("install"), CLI::ParseError);
  EXPECT_FALSE(testInstallArgs.has_value());
}

TEST(CliParserTest, DirectIpRejectsMalformedAddress) {
  testInstallArgs.reset();
  auto app = CliParser::genCliApp(
      installArgs, ignoreClean, ignoreStats, DirectEncapMode::SERVER);
  EXPECT_THROW(app->parse("run --direct-ip=not-an-ip"), CLI::ParseError);
  EXPECT_FALSE(testInstallArgs.has_value());
}

TEST(CliParserTest, ClientHasNoDirectIp) {
  testInstallArgs.reset();
  auto app = CliParser::genCliApp(
      installArgs,
      ignoreClean,
      ignoreStats,
      DirectEncapMode::CLIENT,
      ignorePing);
  EXPECT_THROW(app->parse("run --direct-ip=c0de::1"), CLI::ParseError);
  EXPECT_FALSE(testInstallArgs.has_value());
}

/* vip filter tests */
TEST(CliParserTest, NoVipFilter) {
  testInstallArgs.reset();
  auto app = CliParser::genCliApp(
      installArgs, ignoreClean, ignoreStats, DirectEncapMode::SERVER);
  app->parse("run --direct-ip=c0de::1");
  ASSERT_TRUE(testInstallArgs.has_value());
  EXPECT_FALSE(testInstallArgs->vipsEnabled.has_value());
  EXPECT_FALSE(testInstallArgs->vipsDisabled.has_value());
}

TEST(CliParserTest, VipFilterWithEmptyString) {
  testInstallArgs.reset();
  auto app = CliParser::genCliApp(
      installArgs, ignoreClean, ignoreStats, DirectEncapMode::SERVER);
  app->parse("run --direct-ip=c0de::1 --vips-enabled=");
  ASSERT_TRUE(testInstallArgs.has_value());
  ASSERT_TRUE(testInstallArgs->vipsEnabled.has_value());
  EXPECT_EQ(testInstallArgs->vipsEnabled, "");
  EXPECT_FALSE(testInstallArgs->vipsDisabled.has_value());
  /* same test for disabled */
  testInstallArgs.reset();
  app = CliParser::genCliApp(
      installArgs, ignoreClean, ignoreStats, DirectEncapMode::SERVER);
  app->parse("run --direct-ip=c0de::1 --vips-disabled=");
  ASSERT_TRUE(testInstallArgs.has_value());
  EXPECT_FALSE(testInstallArgs->vipsEnabled.has_value());
  ASSERT_TRUE(testInstallArgs->vipsDisabled.has_value());
  EXPECT_TRUE(testInstallArgs->vipsDisabled->empty());
}

TEST(CliParserTest, VipFilterBothEnabled) {
  testInstallArgs.reset();
  auto app = CliParser::genCliApp(
      installArgs, ignoreClean, ignoreStats, DirectEncapMode::SERVER);
  EXPECT_THROW(
      app->parse(
          "run --direct-ip=c0de::1 --vips-enabled=c0de::1 "
          "--vips-disabled=c0de::2"),
      CLI::ParseError);
  EXPECT_FALSE(testInstallArgs.has_value());
}

} // namespace
} // namespace katran_de::ctl
