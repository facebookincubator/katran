// (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.

#include "katran/kde/ctl/KatranDeThrift.h"

#include <stdexcept>

#include <fb303/ThreadCachedServiceData.h>
#include <thrift/lib/cpp2/server/ThriftServer.h>

namespace katran_de::ctl {

KatranDeServiceHandler::KatranDeServiceHandler()
    : BaseService("KatranDirectEncapService") {}

facebook::fb303::cpp2::fb303_status KatranDeServiceHandler::getStatus() {
  return facebook::fb303::cpp2::fb303_status::ALIVE;
}

void KatranDeServiceHandler::setOption(
    std::unique_ptr<std::string> /* key */,
    std::unique_ptr<std::string> /* value */) {
  throw std::runtime_error("setOption is disabled on katran_de");
}

bool startCounterExport(
    int port,
    apache::thrift::util::ScopedServerThread& thriftThread) {
  return startCounterExport(
      port, thriftThread, std::make_shared<KatranDeServiceHandler>());
}

bool startCounterExport(
    int port,
    apache::thrift::util::ScopedServerThread& thriftThread,
    std::shared_ptr<KatranDeServiceHandler> handler) {
  if (port <= 0) {
    return true;
  }
  auto thriftServer = std::make_shared<apache::thrift::ThriftServer>();
  thriftServer->setInterface(std::move(handler));
  thriftServer->setPort(port);
  // By default, Thrift server will create thread per core. We only serve
  // stats and status, thus 2 threads should be enough.
  thriftServer->setNumIOWorkerThreads(2);
  thriftServer->disableInfoLogging();

  LOG(INFO) << "Starting Thrift server on port " << port;
  try {
    // start() blocks until the server is listening and throws on failure.
    thriftThread.start(std::move(thriftServer));
  } catch (const std::exception& e) {
    LOG(ERROR) << "Thrift server error: " << e.what();
    return false;
  }

  // Counters are bumped in thread-local caches; without this they never reach
  // ServiceData and a scrape would return stale values.
  facebook::fb303::ThreadCachedServiceData::getShared()->startPublishThread(
      std::chrono::milliseconds(-1));
  return true;
}

} // namespace katran_de::ctl
