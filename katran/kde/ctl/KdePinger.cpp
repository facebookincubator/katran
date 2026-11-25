#include "katran/kde/ctl/KdePinger.h"

#include <algorithm>
#include <chrono>
#include <iostream>
#include <numeric>
#include <vector>

#include <bpf/bpf.h>
#include <fmt/format.h>
#include <folly/IPAddress.h>
#include <folly/SocketAddress.h>
#include <folly/Synchronized.h>
#include <folly/futures/Future.h>
#include <folly/io/async/AsyncSocket.h>
#include <folly/io/async/EventBase.h>
#include <folly/io/async/EventBaseManager.h>
#include <folly/io/async/ScopedEventBaseThread.h>
#include <glog/logging.h>

#include "katran/kde/bpf/kde_types.h"
#include "katran/kde/core/KdeBpfUtil.h"

namespace katran_de {
namespace ctl {

namespace {

class TcpConnectCallback : public folly::AsyncSocket::ConnectCallback,
                           public folly::DelayedDestruction {
 public:
  using UniquePtr = std::
      unique_ptr<TcpConnectCallback, folly::DelayedDestruction::Destructor>;

  explicit TcpConnectCallback(folly::EventBase* evb, int skStoreMapFd)
      : skStoreMapFd_(skStoreMapFd),
        socket_(folly::AsyncSocket::UniquePtr(new folly::AsyncSocket(evb))) {}

  void connectSuccess() noexcept override {
    folly::DelayedDestruction::DestructorGuard dg(this);

    // Lookup socket FD in sk_storage map
    if (skStoreMapFd_ >= 0 && socket_) {
      folly::SocketAddress localAddr;
      socket_->getLocalAddress(&localAddr);
      uint16_t clientPort = localAddr.getPort();

      int sockFd = socket_->getNetworkSocket().toFd();
      encap_sk_info skInfo{};

      int ret = bpf_map_lookup_elem(skStoreMapFd_, &sockFd, &skInfo);
      if (ret == 0) {
        folly::IPAddressV6 directIp = folly::IPAddressV6::fromBinary(
            folly::ByteRange(
                reinterpret_cast<const uint8_t*>(&skInfo.direct_ip.v6addr),
                sizeof(skInfo.direct_ip.v6addr)));
        VLOG(1) << "Socket fd=" << sockFd << " sport=" << clientPort
                << " has direct encap IP: " << directIp.str();
        // print to stdout just the direct IP for easy parsing
        std::cout << fmt::format("{}\n", directIp.str());
      } else {
        LOG(ERROR) << "Socket fd=" << sockFd << " sport=" << clientPort
                   << " not found in sk_storage map (ret: " << ret << ")";
      }
    }

    if (socket_) {
      socket_->close();
    }

    promise_.setValue(
        folly::makeExpected<folly::AsyncSocketException>(folly::unit));
  }

  void connectErr(const folly::AsyncSocketException& ex) noexcept override {
    folly::DelayedDestruction::DestructorGuard dg(this);
    promise_.setValue(folly::makeUnexpected(ex));
  }

  folly::Future<folly::Expected<folly::Unit, folly::AsyncSocketException>>
  connect(const folly::SocketAddress& address, int timeoutMs) {
    auto future = promise_.getFuture();
    socket_->connect(this, address, timeoutMs);
    return future;
  }

 private:
  ~TcpConnectCallback() override = default;

  int skStoreMapFd_;
  folly::AsyncSocket::UniquePtr socket_;
  folly::Promise<folly::Expected<folly::Unit, folly::AsyncSocketException>>
      promise_;
};

} // namespace

KdePinger::KdePinger(int threadCount) : threadCount_(threadCount) {
  auto mapFdExp = katran_tpr::KdeBpfUtil::findSkStoreMapFd();
  if (mapFdExp.hasError()) {
    LOG(FATAL) << "Failed to find sk_storage map FD: "
               << mapFdExp.error().what();
  } else {
    skStoreMapFd_ = mapFdExp.value();
    LOG(INFO) << "Loaded sk_storage map FD using KdeBpfUtil: " << skStoreMapFd_;
  }
}

void KdePinger::ping(const folly::IPAddress& ipAddr, uint16_t port, int count) {
  folly::SocketAddress address(ipAddr, port);

  int actualThreadCount = threadCount_;
  if (actualThreadCount == 0) {
    actualThreadCount = std::min(10, std::max(1, count / 10));
  }

  LOG(INFO) << "Starting TCP ping to " << address.describe() << " (" << count
            << " connections on " << actualThreadCount << " threads)";

  struct PingStats {
    std::vector<std::chrono::microseconds> connectionTimes;
    int successCount{0};
    int failureCount{0};
  };
  folly::Synchronized<PingStats> stats;

  auto overallStart = std::chrono::steady_clock::now();

  std::vector<std::unique_ptr<folly::ScopedEventBaseThread>> threads;
  threads.reserve(actualThreadCount);
  for (int i = 0; i < actualThreadCount; ++i) {
    threads.emplace_back(std::make_unique<folly::ScopedEventBaseThread>());
  }

  std::vector<folly::Future<folly::Unit>> futures;
  futures.reserve(count);

  for (int i = 0; i < count; ++i) {
    int threadIdx = i % actualThreadCount;
    auto* evb = threads[threadIdx]->getEventBase();

    folly::Promise<folly::Unit> promise;
    auto future = promise.getFuture();

    evb->runInEventBaseThread([this,
                               evb,
                               address,
                               i,
                               count,
                               &stats,
                               promise = std::move(promise)]() mutable {
      constexpr int kTimeoutMs = 5000;
      auto start = std::chrono::steady_clock::now();

      auto callback = new TcpConnectCallback(evb, skStoreMapFd_);
      TcpConnectCallback::UniquePtr callbackPtr(callback);

      callback->connect(address, kTimeoutMs)
          .thenTry([i,
                    count,
                    start,
                    &stats,
                    callbackPtr = std::move(callbackPtr),
                    promise = std::move(promise)](
                       folly::Try<folly::Expected<
                           folly::Unit,
                           folly::AsyncSocketException>>&& result) mutable {
            auto end = std::chrono::steady_clock::now();
            auto duration =
                std::chrono::duration_cast<std::chrono::microseconds>(
                    end - start);

            if (result.hasValue() && result->hasValue()) {
              stats.withWLock([&](auto& s) {
                s.connectionTimes.push_back(duration);
                s.successCount++;
              });
            } else {
              stats.withWLock([&](auto& s) { s.failureCount++; });

              if (result.hasException()) {
                LOG(WARNING) << "Connection " << (i + 1)
                             << " exception: " << result.exception().what();
              } else if (result.hasValue() && result->hasError()) {
                LOG(WARNING) << "Connection " << (i + 1)
                             << " failed: " << result->error().what();
              }
            }

            stats.withWLock([count](auto& s) {
              int iters = s.successCount + s.failureCount;
              int tenPct = std::max(count / 10, 10);
              if (iters % tenPct == 0 || iters == 1) {
                LOG(INFO) << "Progress: " << iters << "/" << count
                          << " connections completed";
              }
            });

            promise.setValue(folly::unit);
          });
    });

    futures.push_back(std::move(future));
  }

  folly::collectAll(futures).wait();

  auto overallEnd = std::chrono::steady_clock::now();
  auto totalTime = std::chrono::duration_cast<std::chrono::milliseconds>(
      overallEnd - overallStart);

  stats.withRLock([&](const auto& s) {
    LOG(INFO) << "\n========== TCP Ping Statistics ==========";
    LOG(INFO) << "Target: " << address.describe();
    LOG(INFO) << "Total connections attempted: " << count;
    LOG(INFO) << "Successful connections: " << s.successCount;
    LOG(INFO) << "Failed connections: " << s.failureCount;
    LOG(INFO) << "Total time: " << totalTime.count() << " ms";
    LOG(INFO) << "Threads used: " << actualThreadCount;

    if (!s.connectionTimes.empty()) {
      auto minTime =
          *std::min_element(s.connectionTimes.begin(), s.connectionTimes.end());
      auto maxTime =
          *std::max_element(s.connectionTimes.begin(), s.connectionTimes.end());
      auto avgTime = std::accumulate(
                         s.connectionTimes.begin(),
                         s.connectionTimes.end(),
                         std::chrono::microseconds(0)) /
          s.connectionTimes.size();

      LOG(INFO) << "Connection times - Min: " << minTime.count()
                << " μs, Max: " << maxTime.count()
                << " μs, Avg: " << avgTime.count() << " μs";
    }
    LOG(INFO) << "=========================================\n";
  });
}

} // namespace ctl
} // namespace katran_de
