// (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.

#pragma once

#include <functional>
#include <memory>
#include <string>

#include <fb303/BaseService.h>
#include <thrift/lib/cpp2/server/ThriftServer.h>
#include <thrift/lib/cpp2/util/ScopedServerThread.h>

namespace katran_de::ctl {

class KatranDeServiceHandler : public facebook::fb303::BaseService {
 public:
  KatranDeServiceHandler();
  facebook::fb303::cpp2::fb303_status getStatus() override;

  // Throws: the port has no ACL, so any client could rewrite options.
  [[noreturn]] void setOption(
      std::unique_ptr<std::string> key,
      std::unique_ptr<std::string> value) override;
};

// Makes katran_de.* fb303 counters readable over thrift: serves them on
// `thread`, and starts the publish thread that flushes thread-local counters
// into ServiceData. Both halves are needed for a scrape to return current
// values.
//
// No-op if port <= 0. Returns false if the server could not start, leaving the
// caller to decide how to clean up.
bool startCounterExport(
    int port,
    apache::thrift::util::ScopedServerThread& thread);

// Same, but serves `handler`, a KatranDeServiceHandler that also implements a
// service extending fb303 BaseService. `configureServer`, if set, runs before
// the server starts, e.g. to set up TLS.
bool startCounterExport(
    int port,
    apache::thrift::util::ScopedServerThread& thread,
    std::shared_ptr<KatranDeServiceHandler> handler,
    const std::function<void(apache::thrift::ThriftServer&)>& configureServer);

} // namespace katran_de::ctl
