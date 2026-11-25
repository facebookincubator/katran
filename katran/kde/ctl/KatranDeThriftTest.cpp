// (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.

#include <memory>
#include <string>

#include <fb303/thrift/gen-cpp2/BaseServiceAsyncClient.h>
#include <folly/SocketAddress.h>
#include <folly/portability/GTest.h>
#include <folly/testing/TestUtil.h>
#include <thrift/lib/cpp/TApplicationException.h>
#include <thrift/lib/cpp2/util/ScopedServerInterfaceThread.h>

#include "katran/kde/ctl/KatranDeThrift.h"

namespace katran_de::ctl {
namespace {

using Fb303Client = apache::thrift::Client<facebook::fb303::cpp2::BaseService>;

TEST(KatranDeServiceHandlerTest, RejectsSetOption) {
  // Unix socket: the test has no network, loopback included.
  folly::test::TemporaryDirectory socketDir;
  apache::thrift::ScopedServerInterfaceThread server(
      std::make_shared<KatranDeServiceHandler>(),
      folly::SocketAddress::makeFromPath(
          (socketDir.path() / "thrift.sock").string()));
  auto client = server.newClient<Fb303Client>();

  EXPECT_THROW(
      client->sync_setOption("vips_to_inject", "2401:db00::bad"),
      apache::thrift::TApplicationException);

  std::string vipsToInject;
  client->sync_getOption(vipsToInject, "vips_to_inject");
  EXPECT_EQ(vipsToInject, "");
}

} // namespace
} // namespace katran_de::ctl
