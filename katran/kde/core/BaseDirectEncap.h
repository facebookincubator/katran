#pragma once

#include <folly/IPAddress.h>
#include <folly/SocketAddress.h>
#include <glog/logging.h>
#include <katran/kde/consts.h>
#include <katran/lib/BpfAdapter.h>
#include <katran/tpr/bpf_util/BpfSkeleton.h>
#include <linux/types.h>
#include <string>
#include <vector>

// kde_types.h must be before the skel.h as they refrence types
#include "katran/kde/bpf/kde_types.h"
//
#include <katran/kde/bpf/katran_de_so_bpf.skel.h>

namespace katran_tpr {

enum class DirectEncapMode : uint8_t { CLIENT = 0, SERVER = 1 };

/* TODO(shah256): Ideally callers pass zone strings and DirectEncap hides all
 * the parsing details from callers. Callers also do not need to parse. But,
 * Today MetaTcpPktRouter (server/client init, TPR zones) and revproxy's QUIC
 * config take kde_zone masks, so parsing stays a free function until they
 * move behind the API. */

/* Empty means zone 1; `none` and `all` must be used alone. Crashes on
 * invalid input. */
kde_zone parseZones(
    const std::string& csvZones,
    decltype(oss_kde_zones)& zoneMap);

class BaseDirectEncap {
 public:
  BaseDirectEncap(
      const std::string& iface,
      decltype(oss_kde_zones)& zoneMap,
      bool set_limits = false);

  virtual ~BaseDirectEncap();
  BaseDirectEncap(const BaseDirectEncap&) = delete;
  BaseDirectEncap& operator=(const BaseDirectEncap&) = delete;
  BaseDirectEncap(BaseDirectEncap&&) = delete;
  BaseDirectEncap& operator=(BaseDirectEncap&&) = delete;

  virtual folly::Expected<folly::Unit, std::system_error> init() = 0;

  // reset BPF program FDs, so they are not removed in dtor
  virtual void detach() = 0;

  void setCgroupPath(const std::string& cgroupPath);
  void setPin(bool pin);

  void setLogConfig(
      KDE_LOG_LEVEL level,
      KDE_LOG_LEVEL filterLevel,
      uint16_t localPort,
      uint16_t remotePort,
      std::optional<folly::IPAddress> remoteAddr);

  kde_stats getSoStats();

  virtual DirectEncapMode getDirectEncapMode() const = 0;

  // names of the zones set in `zones`, or none, all or unknown
  std::vector<std::string> zoneNames(kde_zone zones) const;

  int getSoProgFd() const {
    return soProgFd_;
  }

  decltype(oss_kde_zones)& zoneMap() const {
    return zoneMap_;
  }

  // Removes KDE TC and SockOps BPF progs if any installed. Use tcHandle = 0
  // in order to remove all installed TC progs.
  static folly::Expected<folly::Unit, std::system_error> clean(
      const std::string& cgroupPath,
      const std::string& iface,
      uint32_t tcHandle);
  static folly::Expected<folly::Unit, std::system_error> cleanSockOps(
      const std::string& cgroupPath);
  static folly::Expected<folly::Unit, std::system_error> cleanTC(
      const std::string& iface,
      uint32_t handle);

 protected:
  virtual folly::Expected<folly::Unit, std::system_error> setSockopsVars() = 0;
  static void rmPinned();
  folly::Expected<folly::Unit, std::system_error> pin(
      bpf_map* map_bss,
      const std::string& bssPath,
      int progFd,
      const std::string& progPath);
  folly::Expected<folly::Unit, std::system_error> crashRecovery();
  void setLogSockopsVars();

  folly::Expected<folly::Unit, std::system_error> loadSockOps();

  std::string modeStr(DirectEncapMode mode);

  KDE_LOG_LEVEL logLevel_{KDE_LOG_OFF};
  KDE_LOG_LEVEL filterLogLevel_{KDE_LOG_OFF};
  uint16_t logLocalPort_{0};
  uint16_t logRemotePort_{0};
  folly::IPAddress logRemoteAddr_;

  std::string cgroupPath_;
  katran::BpfAdapter adapter_;

  BpfSkeleton<katran_de_so_bpf> soSkel_;
  std::string iface_;
  decltype(oss_kde_zones)& zoneMap_;

  int soProgFd_{0};
  int cgroupFd_{0};
  bool pin_{false};
};

} // namespace katran_tpr
