#include "katran/kde/ctl/Commands.h"

#include <signal.h>
#include <unistd.h>

#include <folly/IPAddress.h>
#include <folly/io/async/AsyncSignalHandler.h>
#include <folly/io/async/ScopedEventBaseThread.h>
#include <glog/logging.h>

#include "katran/facebook/cpr/kde/ClientDirectEncap.h"
#include "katran/facebook/cpr/kde/KdeBpfUtil.h"
#include "katran/facebook/direct_encap/api/DirectEncapClientApi.h"
#include "katran/facebook/direct_encap/katran_de_ctl/KdePinger.h"

namespace katran_de::ctl {

void clean(const CleanArgs& cleanArgs) {
  auto res = katran_tpr::ClientDirectEncap::clean(
      cleanArgs.cgroup, cleanArgs.iface, 0);
  // TODO(longterm): either automate cgroup detection else FAIL early if not
  // passed in as an arg. current approach causes confusion when it fails.
  if (res.hasError()) {
    LOG(ERROR) << "Failed to clean Katran DirectEncap: " << res.error().what();
  } else {
    LOG(INFO) << "Katran DirectEncap is cleaned up";
  }
}

void stats(const StatsArgs& statsArgs, bool statusCheck) {
  // TODO(longterm): remove version checks, bin/bpf always distributed as one
  // pkg
  if (statsArgs.skipVersionCheck) {
    LOG(WARNING)
        << "--skip-version-check is deprecated and a no-op; the version check is "
           "off by default. Remove it; use --version-check to opt in.";
  }
  auto soMap = katran_tpr::KdeBpfUtil::findSockOpsBssMap(statsArgs.cgroup);
  if (soMap.hasError()) {
    LOG(ERROR) << "Failed to find Katran DirectEncap sockops map: "
               << soMap.error().what();
    exit(1);
  }
  auto tcMap = katran_tpr::KdeBpfUtil::findTcBssMap(statsArgs.iface);
  if (tcMap.hasError()) {
    LOG(ERROR) << "Failed to find Katran DirectEncap TC map: "
               << tcMap.error().what();
    exit(1);
  }

  // TODO: remove internal versions before ossing
  if (statsArgs.versionCheck && !statsArgs.skipVersionCheck) {
    auto maybeSoVersion =
        katran_tpr::KdeBpfUtil::findSockOpsVersion(statsArgs.cgroup);
    if (maybeSoVersion.hasError()) {
      LOG(ERROR) << "Failed to find Katran DirectEncap sockops version: "
                 << maybeSoVersion.error().what();
      exit(1);
    }
    auto maybeTcVersion =
        katran_tpr::KdeBpfUtil::findTcVersion(statsArgs.iface);
    if (maybeTcVersion.hasError()) {
      LOG(ERROR) << "Failed to find Katran DirectEncap TC version: "
                 << maybeTcVersion.error().what();
      exit(1);
    }
    auto currentVer = katran_tpr::KdeBpfUtil::getCurrentKdeProgVersion();
    auto soVer = *maybeSoVersion;
    auto tcVer = *maybeTcVersion;
    if (soVer == currentVer && tcVer == currentVer) {
      LOG(INFO) << "Katran DirectEncap bpf progs version matched: "
                << KDE_PROG_VERSION;
    } else {
      LOG(ERROR)
          << "Katran DirectEncap bpf progs version mismatch, katran_de_ctl= "
          << currentVer << ", installed so= " << soVer
          << ", installed tc= " << tcVer;
      exit(1);
    }
  }

  StatsPrinter printer(
      statsArgs.details, statsArgs.json, statsArgs.jsonDeltaSec);
  int count = 0;
  while (true) {
    auto newSoStats = katran_tpr::KdeBpfUtil::aggregateSoStats(*soMap->map_);
    auto newTcStats = katran_tpr::KdeBpfUtil::aggregateTcStats(*tcMap->map_);
    printer.printNewStats(newSoStats, newTcStats);
    if (statsArgs.json) {
      if (statsArgs.jsonDeltaSec == 0) {
        // raw stats neeeds only single loop
        break;
      } else if (count > 0) {
        // second loop for json delta stats
        break;
      } else {
        // first loop for json delta stats
        sleep(statsArgs.jsonDeltaSec);
      }
    } else {
      if (statsArgs.limit > 0 && count >= statsArgs.limit) {
        break;
      }
      sleep(1);
    }
    count++;
  }

  if (statusCheck) {
    if (printer.totalErrors() > 0) {
      LOG(ERROR) << "Katran DirectEncap is installed but has errors";
      exit(1);
    } else {
      LOG(INFO) << "Katran DirectEncap is installed and running with no errors";
      exit(0);
    }
  }

  exit(0);
}

void ping(const PingArgs& pingArgs) {
  folly::IPAddress ipAddr;
  try {
    ipAddr = folly::IPAddress(pingArgs.ipAddress);
  } catch (const folly::IPAddressFormatException& e) {
    LOG(ERROR) << "Invalid IP address: " << pingArgs.ipAddress << " - "
               << e.what();
    exit(1);
  }
  KdePinger pinger(pingArgs.cgroupPath, pingArgs.threadCount);
  pinger.ping(ipAddr, pingArgs.port, pingArgs.count);
}

void install(const InstallArgs& installArgs) {
  if (!installArgs.directIp.empty()) {
    LOG(ERROR) << "Ip not used for client";
    exit(1);
  }
  folly::ScopedEventBaseThread evbThread;
  folly::CallbackAsyncSignalHandler signalHandler{
      evbThread.getEventBase(), [&](int) noexcept {
        installArgs.onStop();
        katran_de::DirectEncapClientApi::uninstall();
        exit(0);
      }};
  signalHandler.registerSignalHandler(SIGTERM);
  signalHandler.registerSignalHandler(SIGINT);

  // InstallArgs stays CLI-shaped and KdeInstallParams stays CLI-free, so the
  // API keeps working for callers without a command line. The conversion below
  // is the single translation point between them.
  katran_de::KdeInstallParams params{
      .checkJK = installArgs.checkJK,
      .detach = installArgs.detach,
      .cgroupPath = installArgs.cgroup,
      .iface = installArgs.iface,
      .clientZone = static_cast<kde_zone>(installArgs.clientZone),
      .pin = installArgs.pin,
      .kdePort = installArgs.kdePort,
      .hostMode = installArgs.hostMode,
      .otelStats = installArgs.otel,
      .natMode = installArgs.natMode,
  };
  if (!katran_de::DirectEncapClientApi::installWithParams(params)) {
    LOG(ERROR) << "Failed to install Katran DirectEncap";
    exit(1);
  }

  if (installArgs.detach) {
    LOG(INFO) << "Katran DirectEncap client install done, exiting.";
    exit(0);
  }

  if (!installArgs.onStart()) {
    katran_de::DirectEncapClientApi::uninstall();
    exit(1);
  }

  LOG(INFO)
      << "Katran DirectEncap client is running... <Ctlr+C> to exit with cleanup";
  StatsPrinter printer(
      /*details=*/installArgs.details, /*json=*/false, /*jsonDeltaSec=*/0);
  while (true) {
    if (!installArgs.quiet) {
      auto stats = katran_de::DirectEncapClientApi::stats();
      printer.printNewStats(stats.so_stats, stats.tc_stats);
    }
    sleep(1);
  }
}

} // namespace katran_de::ctl
