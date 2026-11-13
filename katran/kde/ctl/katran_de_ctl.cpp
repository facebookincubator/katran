// (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.

#include <CLI/CLI.hpp>
#include <folly/IPAddress.h>
#include <folly/init/Init.h>
#include <folly/io/async/AsyncSignalHandler.h>
#include <folly/io/async/ScopedEventBaseThread.h>
#include <folly/json/dynamic.h>
#include <folly/portability/GFlags.h>
#include <glog/logging.h>
#include <thrift/lib/cpp2/server/ThriftServer.h>
#include "katran/kde/ctl/CliParser.h"
#include "katran/kde/ctl/Commands.h"
#include "katran/kde/ctl/Utils.h"

using namespace katran_de::ctl;

int main(int argc, char* argv[]) {
  auto options = folly::InitOptions().removeFlags(false).useGFlags(false);
  folly::Init init(&argc, &argv, options);

  auto cli = CliParser::genCliApp(
      install, clean, stats, DirectEncapMode::CLIENT, ping);
  CLI11_PARSE(*cli, argc, argv);
  return 0;
}
