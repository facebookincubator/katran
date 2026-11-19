#include <signal.h>
#include <unistd.h>

#include <CLI/CLI.hpp>
#include <folly/IPAddress.h>
#include <folly/init/Init.h>
#include <folly/io/async/AsyncSignalHandler.h>
#include <folly/io/async/ScopedEventBaseThread.h>
#include <glog/logging.h>
#include <thrift/lib/cpp2/util/ScopedServerThread.h>

#include "katran/facebook/cpr/kde/ClientDirectEncap.h"
#include "katran/facebook/direct_encap/katran_de_ctl/KdePinger.h"
#include "katran/kde/api/DirectEncapClientApi.h"
#include "katran/kde/ctl/CliParser.h"
#include "katran/kde/ctl/KatranDeThrift.h"
#include "katran/kde/ctl/Utils.h"

using namespace katran_de::ctl;

namespace {

void install(const InstallArgs& installArgs) {
  folly::ScopedEventBaseThread evbThread;
  apache::thrift::util::ScopedServerThread thriftThread;
  folly::CallbackAsyncSignalHandler signalHandler{
      evbThread.getEventBase(), [&](int) noexcept {
        thriftThread.stop(); // no-op when --thrift-port not set
        katran_de::DirectEncapClientApi::uninstall();
        exit(0);
      }};
  signalHandler.registerSignalHandler(SIGTERM);
  signalHandler.registerSignalHandler(SIGINT);

  katran_de::KdeInstallParams apiArgs{
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
  if (!katran_de::DirectEncapClientApi::installWithParams(apiArgs)) {
    LOG(ERROR) << "Failed to install Katran DirectEncap";
    exit(1);
  }

  if (installArgs.detach) {
    LOG(INFO) << "Katran DirectEncap client install done, exiting.";
    exit(0);
  }

  if (!startCounterExport(installArgs.thriftPort, thriftThread)) {
    katran_de::DirectEncapClientApi::uninstall();
    exit(1);
  }

  LOG(INFO)
      << "Katran DirectEncap client is running... <Ctrl+C> to exit with cleanup";
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

void clean(const CleanArgs& cleanArgs) {
  if (katran_tpr::ClientDirectEncap::clean(cleanArgs.cgroup, cleanArgs.iface, 0)
          .hasError()) {
    exit(1);
  }
}

void stats(const StatsArgs& statsArgs, bool statusCheck) {
  exit(reportStats(statsArgs, statusCheck));
}

void ping(const PingArgs& pingArgs) {
  KdePinger pinger(pingArgs.cgroupPath, pingArgs.threadCount);
  pinger.ping(
      folly::IPAddress(pingArgs.ipAddress), pingArgs.port, pingArgs.count);
}

} // namespace

int main(int argc, char* argv[]) {
  auto options = folly::InitOptions().removeFlags(false).useGFlags(false);
  folly::Init init(&argc, &argv, options);

  auto cli = CliParser::genCliApp(
      install, clean, stats, DirectEncapMode::CLIENT, ping);
  CLI11_PARSE(*cli, argc, argv);
  return 0;
}
