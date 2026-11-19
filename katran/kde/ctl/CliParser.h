#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include <CLI/CLI.hpp>
#include <folly/IPAddress.h>
#include "katran/facebook/direct_encap/api/DirectEncapApiBase.h"
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
};

struct CleanArgs {
  std::string cgroup;
  std::string iface;
};

struct PingArgs {
  std::string ipAddress;
  uint16_t port{0};
  int count{0};
  std::string cgroupPath;
  int threadCount{0};
};

// single translation point from client CLI args to API params
inline katran_de::KdeInstallParams toClientParams(const InstallArgs& args) {
  return {
      .checkJK = args.checkJK,
      .detach = args.detach,
      .cgroupPath = args.cgroup,
      .iface = args.iface,
      .clientZone = static_cast<kde_zone>(args.clientZone),
      .pin = args.pin,
      .kdePort = args.kdePort,
      .hostMode = args.hostMode,
      .otelStats = args.otel,
      .natMode = args.natMode,
  };
}

class CliParser {
  static const CLI::Validator& ipAddress() {
    static const CLI::Validator validator{
        [](const std::string& value) {
          return folly::IPAddress::tryFromString(value)
              ? std::string{}
              : "is not a valid IP address";
        },
        "IP"};
    return validator;
  }

  static void vipModeFlags(CLI::App* cmd, InstallArgs& args) {
    auto vipsEnabled =
        cmd->add_option(
               "--vips-enabled",
               args.vipsEnabled,
               "Comma separated list of vips to enable kde opts injection in SYN-ACK. If empty, no vips enabled. Max 8 vips.")
            // expected(0, 1) so that an explicit empty list (--vips-enabled=)
            // is accepted: in vip mode it means "inject for no vips at all".
            ->expected(0, 1);
    auto vipsDisabled =
        cmd->add_option(
               "--vips-disabled",
               args.vipsDisabled,
               "Comma separated list of vips to disable kde opts injection in SYN-ACK. If empty, no vips disabled. Max 8 vips.")
            ->expected(0, 1);
    vipsEnabled->excludes(vipsDisabled);
  }

  static void
  parseFlags(CLI::App* cmd, InstallArgs& installArgs, DirectEncapMode mode) {
    cmd->add_option(
           "--cgroup",
           installArgs.cgroup,
           "Cgroup path to install BPF sockops prog. Default assumes execution in Tupperware task environment.")
        ->default_val("");
    cmd->add_option(
           "--iface",
           installArgs.iface,
           "Network interface to install encap BPF prog on. Defaults to eth0.")
        ->default_val("eth0");
    cmd->add_option(
           "--thrift-port",
           installArgs.thriftPort,
           "Port for Thrift server to listen on. Use 0 to disable. Defaults to 0.")
        ->default_val(0);
    cmd->add_flag(
           "--pin-bss",
           installArgs.pin = true,
           "Pin BPF BSS maps to bpffs. Uses LIBBPF_BPF_TOKEN_PATH if set, "
           "else /sys/fs/bpf. Note: requires bpffs mount, not regular directory.")
        ->default_val(false);
    cmd->add_flag(
           "--kde-port",
           installArgs.kdePort = true,
           "Determines whether kdePort 9887 is used. Defaults to GUE port 9886.")
        ->default_val(false);
    cmd->add_flag(
        "--quiet",
        installArgs.quiet,
        "Skip stats printing, by default prints stats every second.");
    cmd->add_flag(
        "--details",
        installArgs.details,
        "Print detailed stats, by default print high level stats only.");
    cmd->add_flag(
        "--otel",
        installArgs.otel,
        "Export KDE stats through OpenTelemetry instead of fb303. Requires OTEL_EXPORTER_OTLP_ENDPOINT.");
    cmd->add_flag(
        "--check-jk",
        installArgs.checkJK,
        "Check if JK is enabled before installing KDE. Defaults to false.");

    if (mode == DirectEncapMode::SERVER) {
      cmd->add_option(
             "--direct-ip", installArgs.directIp, "server's ip address")
          ->required()
          ->check(ipAddress());
      cmd->add_option(
             "--zones",
             installArgs.serverZones,
             "Comma separated list of supported KDE zones. Defaults to origin.")
          ->default_val("origin");
      vipModeFlags(cmd, installArgs);
    } else {
      std::map<std::string, int> map{
          {"none", KDE_ZONE_NONE},
          {"origin", KDE_ZONE_ORIGIN},
          {"edge", KDE_ZONE_EDGE},
          {"rl_corp", KDE_ZONE_RL_CORP},
          {"cloud_cw", KDE_ZONE_CLOUD_CW}};
      cmd->add_option(
             "--zone",
             installArgs.clientZone,
             "client's KDE zone. Defaults to origin.")
          ->default_val(static_cast<int>(KDE_ZONE_ORIGIN))
          ->transform(CLI::CheckedTransformer(std::move(map)));
      cmd->add_flag(
          "--host-mode",
          installArgs.hostMode,
          "Serve all containers on the host from one instance: --iface is the host NIC and connections are tracked by tuple. Defaults to false.");
      cmd->add_flag(
          "--nat-mode",
          installArgs.natMode,
          "Client expected to run behind a NAT. Server echoes observed port along with direct ip, client TC will then rewrite inner sport to match it");
    }
  }

 public:
  static std::unique_ptr<CLI::App> genCliApp(
      void install(const InstallArgs&),
      void clean(const CleanArgs&),
      void stats(const StatsArgs&, bool),
      DirectEncapMode mode,
      void ping(const PingArgs&) = nullptr) {
    auto gflagV = std::make_shared<int>(0);
    auto app = std::make_unique<CLI::App>("Katran DirectEncap CLI");
    app->require_subcommand(1, 1);
    app->set_help_all_flag("--help-all", "Print all options");
    app->fallthrough(); // unknown flags in subcommands try with parent
    app->add_option("-v,--v", *gflagV, "Set glog vlog level");
    app->parse_complete_callback([=]() {
      if (*gflagV > 0) {
        gflags::SetCommandLineOption("minloglevel", "0");
        gflags::SetCommandLineOption("v", std::to_string(*gflagV).c_str());
      }
    });

    {
      auto installArgs = std::make_shared<InstallArgs>();
      CLI::App* installCmd = app->add_subcommand(
          "install", "Installs Katran DirectEncap BPF programs.");
      parseFlags(installCmd, *installArgs, mode);
      installArgs->detach = true;
      installCmd->callback([=]() { install(*installArgs); });
    }

    {
      auto runArgs = std::make_shared<InstallArgs>();
      CLI::App* runCmd = app->add_subcommand(
          "run",
          "Side-car mode, installs Katran DirectEncap BPF programs and keep running until Ctrl+C'ed, printing stats optionally. Removes BPF progs on exit.");
      parseFlags(runCmd, *runArgs, mode);
      runArgs->detach = false;
      runCmd->callback([=]() { install(*runArgs); });
    }

    {
      auto cleanArgs = std::make_shared<CleanArgs>();
      CLI::App* cleanCmd = app->add_subcommand(
          "clean", "Removes Katran DirectEncap BPF programs.");
      cleanCmd
          ->add_option(
              "--cgroup",
              cleanArgs->cgroup,
              "Cgroup path where BPF sockops prog was installed. Default assumes execution in Tupperware task environment.")
          ->default_val("");
      cleanCmd
          ->add_option(
              "--iface",
              cleanArgs->iface,
              "Network interface where encap BPF prog was installed. Defaults to eth0.")
          ->default_val("eth0");
      cleanCmd->add_option("-v,--v", *gflagV, "Set glog vlog level")
          ->default_val(0);
      cleanCmd->callback([=]() { clean(*cleanArgs); });
    }

    {
      auto statsArgs = std::make_shared<StatsArgs>();
      statsArgs->mode = mode;
      CLI::App* statsCmd = app->add_subcommand(
          "stats", "Prints stats from already installed KDE BPF programs.");
      statsCmd
          ->add_option(
              "--cgroup",
              statsArgs->cgroup,
              "Cgroup path where BPF sockops prog was installed. Default assumes execution in Tupperware task environment.")
          ->default_val("");
      statsCmd
          ->add_option(
              "--iface",
              statsArgs->iface,
              "Network interface where encap BPF prog was installed. Defaults to eth0.")
          ->default_val("eth0");
      statsCmd
          ->add_option(
              "-l,--limit",
              statsArgs->limit,
              "Limit number of stats to print. Defaults to 0, which keeps printing stats indefinetely.")
          ->default_val(0);
      statsCmd->add_flag(
          "--details",
          statsArgs->details,
          "Print detailed stats, by default print high level stats only.");
      statsCmd->add_flag(
          "--json",
          statsArgs->json,
          "By default stats are printed in single line format. With this flag prints stats in json format, using 60 sec delta by default.");
      statsCmd
          ->add_option(
              "--json-delta-sec",
              statsArgs->jsonDeltaSec,
              "Delta in seconds between stats collection and output to json. Default to 60 sec. Pass 0 to print raw stat values.")
          ->default_val(60);
      statsCmd->add_flag(
          "--version-check",
          statsArgs->versionCheck,
          "Compare the installed KDE BPF program version against this binary and exit with code 1 on mismatch. Off by default.");
      statsCmd->add_flag(
          "--skip-version-check",
          statsArgs->skipVersionCheck,
          "Deprecated, kept only for back-compat: the version check is already off by default, so this is a no-op (and still forces it off). Use --version-check to opt in.");
      statsCmd->add_option("-v,--v", *gflagV, "Set glog vlog level")
          ->default_val(0);
      statsCmd->callback([=]() { stats(*statsArgs, /*statusCheck=*/false); });
    }

    {
      auto statusArgs = std::make_shared<StatsArgs>();
      statusArgs->mode = mode;
      CLI::App* statusCmd = app->add_subcommand(
          "status",
          "Checks if KDE BPF programs are installed successfully and runs with no errors (at the moment of check). Exit code 0 means success, 1 means failure.");
      statusCmd
          ->add_option(
              "--cgroup",
              statusArgs->cgroup,
              "Cgroup path where BPF sockops prog was installed. Default assumes execution in Tupperware task environment.")
          ->default_val("");
      statusCmd
          ->add_option(
              "--iface",
              statusArgs->iface,
              "Network interface where encap BPF prog was installed. Defaults to eth0.")
          ->default_val("eth0");
      statusCmd->add_flag(
          "--version-check",
          statusArgs->versionCheck,
          "Compare the installed KDE BPF program version against this binary and exit with code 1 on mismatch. Off by default.");
      statusCmd->add_flag(
          "--skip-version-check",
          statusArgs->skipVersionCheck,
          "Deprecated, kept only for back-compat: the version check is already off by default, so this is a no-op (and still forces it off). Use --version-check to opt in.");
      statusCmd->add_option("-v,--v", *gflagV, "Set glog vlog level")
          ->default_val(0);
      statusCmd->callback([=]() {
        statusArgs->limit = 2; // check for errors for 2 seconds
        stats(*statusArgs, /*statusCheck=*/true);
      });
    }

    if (mode == DirectEncapMode::CLIENT) {
      CHECK(ping);
      auto pingArgs = std::make_shared<PingArgs>();
      CLI::App* pingCmd =
          app->add_subcommand("ping", "Ping a given IP address.");
      pingCmd
          ->add_option(
              "ip", pingArgs->ipAddress, "Destination IP address to ping")
          ->required()
          ->check(ipAddress());
      pingCmd
          ->add_option(
              "-p,--port",
              pingArgs->port,
              "Port to connect to. Defaults to 443.")
          ->default_val(443);
      pingCmd
          ->add_option(
              "-c,--count",
              pingArgs->count,
              "Number of connections to make. Defaults to 10.")
          ->default_val(10);
      pingCmd
          ->add_option(
              "-t,--threads",
              pingArgs->threadCount,
              "Number of threads to use for parallel connections. Defaults to 0 (auto: min(10, count/10)).")
          ->default_val(0);
      pingCmd
          ->add_option(
              "--cgroup",
              pingArgs->cgroupPath,
              "Cgroup path to find BPF programs. Default assumes execution in Tupperware task environment.")
          ->default_val("");
      pingCmd->add_option("-v,--v", *gflagV, "Set glog vlog level")
          ->default_val(0);
      pingCmd->callback([=]() { ping(*pingArgs); });
    }

    return app;
  }
};

} // namespace katran_de::ctl
