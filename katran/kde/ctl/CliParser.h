// (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.

#pragma once

#include <CLI/CLI.hpp>
#include <folly/IPAddress.h>
#include "katran/kde/ctl/Commands.h"
#include "katran/kde/ctl/Utils.h"

namespace katran_de::ctl {
class CliParser {
  // Rejects values folly cannot parse, so install can convert without
  // re-checking. Callers that reach the API directly validate separately.
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

  static void vipModeFlags(CLI::App* cmd, std::shared_ptr<InstallArgs> args) {
    auto vipsEnabled =
        cmd->add_option(
               "--vips-enabled",
               args->vipsEnabled,
               "Comma separated list of vips to enable kde opts injection in SYN-ACK. If empty, no vips enabled. Max 8 vips.")
            // expected(0, 1) so that an explicit empty list (--vips-enabled=)
            // is accepted: in vip mode it means "inject for no vips at all".
            ->expected(0, 1);
    auto vipsDisabled =
        cmd->add_option(
               "--vips-disabled",
               args->vipsDisabled,
               "Comma separated list of vips to disable kde opts injection in SYN-ACK. If empty, no vips disabled. Max 8 vips.")
            ->expected(0, 1);
    vipsEnabled->excludes(vipsDisabled);
  }

 public:
  static std::unique_ptr<CLI::App> genCliApp(
      void install(const InstallArgs&),
      void clean(const CleanArgs&),
      void stats(const StatsArgs&, bool),
      DirectEncapMode mode,
      void ping(const PingArgs&) = nullptr) {
    auto gflagV = std::make_shared<int>(0);
    auto handleGlobal = [=]() {
      if (*gflagV > 0) {
        gflags::SetCommandLineOption("minloglevel", "0");
        gflags::SetCommandLineOption("v", std::to_string(*gflagV).c_str());
      }
    };

    auto app = std::make_unique<CLI::App>("Katran DirectEncap CLI");
    app->require_subcommand(1, 1);
    app->set_help_all_flag("--help-all", "Print all options");
    app->add_option("-v,--v", *gflagV, "Set glog vlog level")->default_val(0);
    app->parse_complete_callback([=]() { handleGlobal(); });

    // TODO(shah256): only one client uses "install" subcommand. move it to "run
    // --detach" and remove this.
    {
      auto installArgs = std::make_shared<InstallArgs>();
      CLI::App* installCmd = app->add_subcommand(
          "install", "Installs Katran DirectEncap BPF programs.");
      installCmd
          ->add_option(
              "--cgroup",
              installArgs->cgroup,
              "Cgroup path to install BPF sockops prog. Default assumes execution in Tupperware task environment.")
          ->default_val("");
      installCmd
          ->add_option(
              "--iface",
              installArgs->iface,
              "Network interface to install encap BPF prog on. Defaults to eth0.")
          ->default_val("eth0");
      if (mode == DirectEncapMode::SERVER) {
        installCmd
            ->add_option(
                "--direct-ip", installArgs->directIp, "server's ip address")
            ->required()
            ->check(ipAddress());
        installCmd
            ->add_option(
                "--zones",
                installArgs->serverZones,
                "Comma separated list of supported KDE zones. Defaults to origin.")
            ->default_val("origin");
        vipModeFlags(installCmd, installArgs);
      } else {
        std::map<std::string, int> map{
            {"none", KDE_ZONE_NONE},
            {"origin", KDE_ZONE_ORIGIN},
            {"edge", KDE_ZONE_EDGE},
            {"rl_corp", KDE_ZONE_RL_CORP},
            {"cloud_cw", KDE_ZONE_CLOUD_CW}};
        installCmd
            ->add_option(
                "--zone",
                installArgs->clientZone,
                "client's KDE zone. Defaults to origin.")
            ->default_val(static_cast<int>(KDE_ZONE_ORIGIN))
            ->transform(CLI::CheckedTransformer(std::move(map)));
        installCmd->add_flag(
            "--check-jk",
            installArgs->checkJK,
            "Check if JK is enabled before installing KDE. Defaults to false.");
        installCmd->add_flag(
            "--host-mode",
            installArgs->hostMode,
            "Serve all containers on the host from one instance: --iface is the host NIC and connections are tracked by tuple. Defaults to false.");
        installCmd->add_flag(
            "--nat-mode",
            installArgs->natMode,
            "Client expected to run behind a NAT. Server echoes observed port along with direct ip, client TC will then rewrite inner sport to match it");
      }
      installCmd
          ->add_flag(
              "--pin-bss",
              installArgs->pin = true,
              "Pin BPF BSS maps to bpffs. Uses LIBBPF_BPF_TOKEN_PATH if set, "
              "else /sys/fs/bpf. Note: requires bpffs mount, not regular directory.")
          ->default_val(false);
      installCmd
          ->add_flag(
              "--kde-port",
              installArgs->kdePort = true,
              "Determines whether kdePort 9887 is used. Defaults to GUE port 9886.")
          ->default_val(false);
      installCmd->add_option("-v,--v", *gflagV, "Set glog vlog level")
          ->default_val(0);
      installCmd->callback([=]() {
        handleGlobal();
        installArgs->detach = true;
        install(*installArgs);
      });
    }

    {
      auto runArgs = std::make_shared<InstallArgs>();
      CLI::App* runCmd = app->add_subcommand(
          "run",
          "Side-car mode, installs Katran DirectEncap BPF programs and keep running until Ctrl+C'ed, printing stats optionally. Removes BPF progs on exit.");
      runCmd
          ->add_option(
              "--cgroup",
              runArgs->cgroup,
              "Cgroup path to install BPF sockops prog. Default assumes execution in Tupperware task environment.")
          ->default_val("");
      runCmd
          ->add_option(
              "--iface",
              runArgs->iface,
              "Network interface to install encap BPF prog on. Defaults to eth0.")
          ->default_val("eth0");
      runCmd->add_flag(
          "--check-jk",
          runArgs->checkJK,
          "Check if JK is enabled before installing KDE and continue checking to turn off. Defaults to false.");
      if (mode == DirectEncapMode::SERVER) {
        runCmd
            ->add_option(
                "--direct-ip", runArgs->directIp, "server's ip address")
            ->required()
            ->check(ipAddress());
        runCmd
            ->add_option(
                "--zones",
                runArgs->serverZones,
                "Comma separated list of supported KDE zones. Defaults to origin.")
            ->default_val("origin");
        vipModeFlags(runCmd, runArgs);
      } else {
        std::map<std::string, int> map{
            {"none", KDE_ZONE_NONE},
            {"origin", KDE_ZONE_ORIGIN},
            {"edge", KDE_ZONE_EDGE},
            {"rl_corp", KDE_ZONE_RL_CORP},
            {"cloud_cw", KDE_ZONE_CLOUD_CW}};
        runCmd
            ->add_option(
                "--zone",
                runArgs->clientZone,
                "client's KDE zone. Defaults to origin.")
            ->default_val(static_cast<int>(KDE_ZONE_ORIGIN))
            ->transform(CLI::CheckedTransformer(std::move(map)));
        runCmd
            ->add_flag(
                "--kde-port",
                runArgs->kdePort = true,
                "Determines whether kdePort 9887 is used. Defaults to GUE port 9886.")
            ->default_val(false);
        runCmd->add_flag(
            "--host-mode",
            runArgs->hostMode,
            "Serve all containers on the host from one instance: --iface is the host NIC and connections are tracked by tuple. Defaults to false.");
        runCmd->add_flag(
            "--nat-mode",
            runArgs->natMode,
            "Client expected to run behind a NAT. Server echoes observed port along with direct ip, client TC will then rewrite inner sport to match it");
      }
      runCmd->add_flag(
          "--quiet",
          runArgs->quiet,
          "Skip stats printing, by default prints stats every second.");
      runCmd->add_flag(
          "--otel",
          runArgs->otel,
          "Export KDE stats through OpenTelemetry instead of fb303. Requires OTEL_EXPORTER_OTLP_ENDPOINT.");
      runCmd->add_flag(
          "--details",
          runArgs->details,
          "Print detailed stats, by default print high level stats only.");
      runCmd
          ->add_option(
              "--thrift-port",
              runArgs->thriftPort,
              "Port for Thrift server to listen on. Use 0 to disable. Defaults to 0.")
          ->default_val(0);
      runCmd->add_option("-v,--v", *gflagV, "Set glog vlog level")
          ->default_val(0);
      runCmd
          ->add_flag(
              "--pin-bss",
              runArgs->pin = true,
              "Pin BPF BSS maps to bpffs. Uses LIBBPF_BPF_TOKEN_PATH if set, "
              "else /sys/fs/bpf. Note: requires bpffs mount, not regular directory.")
          ->default_val(false);
      runCmd->callback([=]() {
        handleGlobal();
        runArgs->detach = false;
        install(*runArgs);
      });
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
      cleanCmd->callback([=]() {
        handleGlobal();
        clean(*cleanArgs);
      });
    }

    {
      auto statsArgs = std::make_shared<StatsArgs>();
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
      statsCmd->callback([=]() {
        handleGlobal();
        stats(*statsArgs, /*statusCheck=*/false);
      });
    }

    {
      auto statusArgs = std::make_shared<StatsArgs>();
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
        handleGlobal();
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
          ->required();
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
      pingCmd->callback([=]() {
        handleGlobal();
        ping(*pingArgs);
      });
    }

    return app;
  }
};

} // namespace katran_de::ctl
