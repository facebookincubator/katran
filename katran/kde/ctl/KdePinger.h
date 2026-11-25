#pragma once

#include <string>

#include <folly/IPAddress.h>

namespace katran_de {
namespace ctl {

class KdePinger {
 public:
  explicit KdePinger(int threadCount);
  ~KdePinger() = default;

  void ping(const folly::IPAddress& ipAddress, uint16_t port, int count);

 private:
  KdePinger(const KdePinger&) = delete;
  KdePinger& operator=(const KdePinger&) = delete;

  int skStoreMapFd_{-1};
  int threadCount_{0};
};

} // namespace ctl
} // namespace katran_de
