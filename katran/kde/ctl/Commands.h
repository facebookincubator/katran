#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>

#include "katran/kde/ctl/Utils.h"

namespace katran_de::ctl {

struct InstallArgs {
  std::string cgroup;
  std::string iface;
  std::string directIp;
  int clientZone{KDE_ZONE_NONE};
  std::string serverZones;
  bool detach{false};
  bool quiet{false};
  bool details{false};
  int thriftPort{0};
  bool checkJK{false};
  bool pin{false};
  bool kdePort{false};
  bool hostMode{false};
  bool otel{false};
  bool natMode{false};
  // vip mode flags
  std::optional<std::string> vipsEnabled;
  std::optional<std::string> vipsDisabled;
  // hooks unset by default
  std::function<bool()> onStart = [] { return true; };
  std::function<void()> onStop = [] {};
};

struct CleanArgs {
  std::string cgroup;
  std::string iface;
};

struct StatsArgs {
  std::string cgroup;
  std::string iface;
  int limit;
  bool details;
  // The version check is off by default and opt-in via --version-check:
  // KDE_PROG_VERSION is never bumped so it guards nothing in practice, and its
  // cgroup lookup used to fail spuriously. --skip-version-check is deprecated,
  // kept only for back-compat; it is a no-op (and still forces the check off).
  bool versionCheck{false};
  bool skipVersionCheck{false};
  bool json{false};
  int jsonDeltaSec{0};
};

struct PingArgs {
  std::string ipAddress;
  uint16_t port{0};
  int count{0};
  std::string cgroupPath;
  int threadCount{0};
};

void clean(const CleanArgs& cleanArgs);
void stats(const StatsArgs& statsArgs, bool statusCheck);
void ping(const PingArgs& pingArgs);
void install(const InstallArgs& installArgs);
} // namespace katran_de::ctl
