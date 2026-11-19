#pragma once

#include <fmt/core.h>
#include <folly/json/dynamic.h>
#include <folly/json/json.h>
#include <folly/logging/xlog.h>
#include <unistd.h>
#include <iostream>
#include <optional>
#include <string>
#include "katran/facebook/cpr/kde/BaseDirectEncap.h"
#include "katran/facebook/cpr/kde/KdeBpfUtil.h"
#include "katran/kde/bpf/kde_types.h"

namespace katran_de::ctl {

using katran_tpr::DirectEncapMode;

class StatsPrinter {
 public:
  explicit StatsPrinter(
      bool details,
      bool json,
      int jsonDeltaSec,
      DirectEncapMode mode = DirectEncapMode::CLIENT)
      : details_(details),
        json_(json),
        jsonDeltaSec_(jsonDeltaSec),
        mode_(mode) {
    if (jsonDeltaSec_ == 0) {
      suffix_ = ".raw";
    } else {
      suffix_ = fmt::format(".sum.{}", jsonDeltaSec_);
    }
  }

  // Overload for server mode.
  void printNewStats(const kde_stats& so) {
    if (mode_ != DirectEncapMode::SERVER) {
      XLOG(FATAL) << "Called server stats printer in client mode.";
      return;
    }
    if (so_.has_value()) {
      kde_stats diffSo = katran_tpr::KdeBpfUtil::diffSoStats(so, *so_);
      totalErrors_ = katran_tpr::KdeBpfUtil::sumServerErrors(diffSo);
      if (json_) {
        printJson(so);
      } else {
        printText(so);
      }
    }
    if (json_ && jsonDeltaSec_ == 0) {
      printJson(so);
    }
    so_ = so;
  }

  // Overload for client mode.
  void printNewStats(const kde_stats& so, const kde_tc_stats& tc) {
    if (mode_ != DirectEncapMode::CLIENT) {
      XLOG(FATAL) << "Called client stats printer in server mode.";
      return;
    }
    if (so_.has_value() && tc_.has_value()) {
      kde_stats diffSo = katran_tpr::KdeBpfUtil::diffSoStats(so, *so_);
      kde_tc_stats diffTc = katran_tpr::KdeBpfUtil::diffTcStats(tc, *tc_);
      int errSum = diffSo.error_sys_calls + diffSo.client_error_write_opt +
          diffTc.error_sys_calls + diffTc.encap_fail + diffTc.error_parse_src;
      totalErrors_ += errSum;
      if (json_) {
        printJson(so, tc);
      } else {
        printText(so, tc, errSum);
      }
    }
    if (json_ && jsonDeltaSec_ == 0) {
      printJson(so, tc);
    }
    so_ = so;
    tc_ = tc;
  }

  int totalErrors() const {
    return totalErrors_;
  }

 private:
  // Print for server mode.
  void printText(const kde_stats& so) {
    std::string logStr = fmt::format(
        "err={} opt_sent={} retrans_synack={} directip_blackhole={} "
        "no_kde_syn={} ",
        katran_tpr::KdeBpfUtil::sumServerErrors(so),
        so.server_opt_set,
        so.server_retrans_synack,
        so.server_directip_blackhole,
        so.server_no_kde_syn);
    if (details_) {
      logStr += fmt::format("no_kde={} ", so.server_no_kde);
      logStr += "\n  errors: ";
      logStr += fmt::format("sys_calls={} ", so.error_sys_calls);
      logStr += fmt::format("write_opt={} ", so.server_error_write_opt);
      logStr += fmt::format("setso={} ", so.server_error_setso);
      logStr += fmt::format("set_cb={} ", so.server_error_set_cb);
      logStr += fmt::format("unset_cb={} ", so.server_error_unset_cb);
      logStr += fmt::format("load_hdr={} ", so.server_error_load_hdr);
      logStr += fmt::format("reserve={} ", so.server_error_reserve);
      logStr += fmt::format("no_saved_syn={} ", so.server_error_no_saved_syn);
      logStr += fmt::format(
          "synack_map_update={} ", so.server_error_synack_map_update);
      logStr += fmt::format("\n  zones: v1={} ", so.server_rx_zone_v1);
      logStr += fmt::format(
          "accepted u/o/e/r/c={}/{}/{}/{}/{} ",
          so.server_rx_zone_unknown_acc,
          so.server_rx_zone_1_acc,
          so.server_rx_zone_2_acc,
          so.server_rx_zone_3_acc,
          so.server_rx_zone_4_acc);
      logStr += fmt::format(
          "rejected u/o/e/r/c={}/{}/{}/{}/{} ",
          so.server_rx_zone_unknown_rej,
          so.server_rx_zone_1_rej,
          so.server_rx_zone_2_rej,
          so.server_rx_zone_3_rej,
          so.server_rx_zone_4_rej);
    }
    XLOG(INFO) << "Stats per sec: " << logStr;
  }
  void printJson(const kde_stats& so) {
    folly::dynamic jsonObject = folly::dynamic::object(
        "katran_de.server.so_errors" + suffix_,
        katran_tpr::KdeBpfUtil::sumServerErrors(so))(
        "katran_de.server.error.sys_calls" + suffix_, so.error_sys_calls)(
        "katran_de.server.error.write_opt" + suffix_,
        so.server_error_write_opt)(
        "katran_de.server.error.setso" + suffix_, so.server_error_setso)(
        "katran_de.server.error.set_cb" + suffix_, so.server_error_set_cb)(
        "katran_de.server.error.unset_cb" + suffix_, so.server_error_unset_cb)(
        "katran_de.server.error.load_hdr" + suffix_, so.server_error_load_hdr)(
        "katran_de.server.error.reserve" + suffix_, so.server_error_reserve)(
        "katran_de.server.error.no_saved_syn" + suffix_,
        so.server_error_no_saved_syn)(
        "katran_de.server.error.synack_map_update" + suffix_,
        so.server_error_synack_map_update)(
        "katran_de.server.opt_sent" + suffix_, so.server_opt_set)(
        "katran_de.server.retrans_synack" + suffix_, so.server_retrans_synack)(
        "katran_de.server.directip.blackhole" + suffix_,
        so.server_directip_blackhole)(
        "katran_de.server.server.rx_zone.v1" + suffix_, so.server_rx_zone_v1)(
        "katran_de.server.server.rx_zone.origin.acc" + suffix_,
        so.server_rx_zone_1_acc)(
        "katran_de.server.server.rx_zone.edge.acc" + suffix_,
        so.server_rx_zone_2_acc)(
        "katran_de.server.server.rx_zone.rl_corp.acc" + suffix_,
        so.server_rx_zone_3_acc)(
        "katran_de.server.server.rx_zone.cloud_cw.acc" + suffix_,
        so.server_rx_zone_4_acc)(
        "katran_de.server.server.rx_zone.unknown.acc" + suffix_,
        so.server_rx_zone_unknown_acc)(
        "katran_de.server.server.rx_zone.origin.rej" + suffix_,
        so.server_rx_zone_1_rej)(
        "katran_de.server.server.rx_zone.edge.rej" + suffix_,
        so.server_rx_zone_2_rej)(
        "katran_de.server.server.rx_zone.rl_corp.rej" + suffix_,
        so.server_rx_zone_3_rej)(
        "katran_de.server.server.rx_zone.cloud_cw.rej" + suffix_,
        so.server_rx_zone_4_rej)(
        "katran_de.server.server.rx_zone.unknown.rej" + suffix_,
        so.server_rx_zone_unknown_rej)("timestamp", timestamp());
    std::cout << folly::toJson(jsonObject) << std::endl;
  }

  // Print for client mode.
  void printText(const kde_stats& so, const kde_tc_stats& tc, int errSum) {
    std::string logStr = fmt::format(
        "encap={} encap_bytes={} err={} opt_sent={} opt_rcvd={}",
        tc.encap_ok,
        tc.encap_bytes,
        errSum,
        so.client_opt_set,
        so.client_opt_received);
    if (details_) {
      logStr += fmt::format("  SO: error_sys_calls={} ", so.error_sys_calls);
      logStr += fmt::format("opt_set={} ", so.client_opt_set);
      logStr += fmt::format("error_write_opt={} ", so.client_error_write_opt);
      logStr += fmt::format("no_kde={} ", so.client_no_kde);
      logStr += fmt::format("opt_received={} ", so.client_opt_received);
      logStr += fmt::format("sk_stored={} ", so.client_sk_stored);
      logStr += fmt::format("tuple_stored={} ", so.client_tuple_stored);
      logStr += fmt::format("tuple_removed={} ", so.client_tuple_removed);
      logStr += fmt::format(
          "tuple_store_stale_entries={} ", so.client_tuple_store_stale_entries);
      logStr +=
          fmt::format("error_tuple_store={} ", so.client_error_tuple_store);
      logStr += fmt::format("   TC: error_sys_calls={} ", tc.error_sys_calls);
      logStr += fmt::format("no_sk_store={} ", tc.no_sk_store);
      logStr += fmt::format("in_sk_store={} ", tc.in_sk_store);
      logStr += fmt::format("no_tuple_store={} ", tc.no_tuple_store);
      logStr += fmt::format("in_tuple_store={} ", tc.in_tuple_store);
      logStr += fmt::format("encap_fail={} ", tc.encap_fail);
      logStr += fmt::format("encap_ok={} ", tc.encap_ok);
      logStr += fmt::format("encap_bytes={} ", tc.encap_bytes);
      logStr += fmt::format("encap_payload_bytes={} ", tc.encap_payload_bytes);
      logStr += fmt::format("error_parse_src={} ", tc.error_parse_src);
    }
    XLOG(INFO) << "Stats per sec: " << logStr;
  }
  void printJson(const kde_stats& so, const kde_tc_stats& tc) {
    folly::dynamic jsonObject = folly::dynamic::object(
        "katran_de.client.so_errors" + suffix_,
        so.error_sys_calls + so.client_error_write_opt)(
        "katran_de.client.tc_errors" + suffix_,
        tc.error_sys_calls + tc.encap_fail)(
        "katran_de.client.opt_sent" + suffix_, so.client_opt_set)(
        "katran_de.client.opt_received" + suffix_, so.client_opt_received)(
        "katran_de.client.encap_pckts" + suffix_, tc.encap_ok)(
        "katran_de.client.encap_bytes" + suffix_, tc.encap_bytes)(
        "katran_de.client.encap_payload_bytes" + suffix_,
        tc.encap_payload_bytes)("timestamp", timestamp());
    std::cout << folly::toJson(jsonObject) << std::endl;
  }

  std::string timestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_time_t = std::chrono::system_clock::to_time_t(now);
    std::tm* local_tm = std::localtime(&now_time_t);
    return fmt::format(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        local_tm->tm_year + 1900,
        local_tm->tm_mon + 1,
        local_tm->tm_mday,
        local_tm->tm_hour,
        local_tm->tm_min,
        local_tm->tm_sec);
  }

  int totalErrors_{0};
  bool details_;
  bool json_;
  int jsonDeltaSec_;
  std::string suffix_;
  std::optional<kde_stats> so_ = std::nullopt;
  std::optional<kde_tc_stats> tc_ = std::nullopt; // used only in client mode.
  DirectEncapMode mode_;
};

// Reads stats of a KDE that another process installed, by finding its BPF
// maps through the cgroup (sockops) and, for clients, the interface (TC).
struct StatsArgs {
  std::string cgroup;
  std::string iface;
  DirectEncapMode mode{DirectEncapMode::CLIENT};
  // number of samples to print, 0 prints forever; ignored with json
  int limit{0};
  bool details{false};
  // The version check is off by default and opt-in via --version-check:
  // KDE_PROG_VERSION is never bumped so it guards nothing in practice, and its
  // cgroup lookup used to fail spuriously. --skip-version-check is deprecated,
  // kept only for back-compat; it is a no-op (and still forces the check off).
  bool versionCheck{false};
  bool skipVersionCheck{false};
  bool json{false};
  // with json: 0 prints raw counters once, N prints the delta over N seconds
  int jsonDeltaSec{0};
};

// Prints stats of the installed KDE. With statusCheck, also reports whether it
// saw errors. Returns the process exit code: 0 on success, 1 if KDE is not
// installed, its version mismatches, or (with statusCheck) it has errors.
inline int reportStats(const StatsArgs& args, bool statusCheck) {
  const bool client = args.mode == DirectEncapMode::CLIENT;
  if (args.skipVersionCheck) {
    XLOG(WARN)
        << "--skip-version-check is deprecated and a no-op; the version check is "
           "off by default. Remove it; use --version-check to opt in.";
  }
  auto soMap = katran_tpr::KdeBpfUtil::findSockOpsBssMap(args.cgroup);
  if (soMap.hasError()) {
    XLOG(ERR) << "Failed to find Katran DirectEncap sockops map: "
              << soMap.error().what();
    return 1;
  }
  std::optional<katran_tpr::TcBssMap> tcMap;
  if (client) {
    auto maybeTcMap = katran_tpr::KdeBpfUtil::findTcBssMap(args.iface);
    if (maybeTcMap.hasError()) {
      XLOG(ERR) << "Failed to find Katran DirectEncap TC map: "
                << maybeTcMap.error().what();
      return 1;
    }
    tcMap = std::move(*maybeTcMap);
  }

  if (args.versionCheck && !args.skipVersionCheck) {
    auto currentVer = katran_tpr::KdeBpfUtil::getCurrentKdeProgVersion();
    auto soVer = katran_tpr::KdeBpfUtil::findSockOpsVersion(args.cgroup);
    if (soVer.hasError()) {
      XLOG(ERR) << "Failed to find Katran DirectEncap sockops version: "
                << soVer.error().what();
      return 1;
    }
    if (*soVer != currentVer) {
      XLOG(ERR)
          << "Katran DirectEncap bpf progs version mismatch, katran_de_ctl= "
          << currentVer << ", installed so= " << *soVer;
      return 1;
    }
    if (client) {
      auto tcVer = katran_tpr::KdeBpfUtil::findTcVersion(args.iface);
      if (tcVer.hasError()) {
        XLOG(ERR) << "Failed to find Katran DirectEncap TC version: "
                  << tcVer.error().what();
        return 1;
      }
      if (*tcVer != currentVer) {
        XLOG(ERR)
            << "Katran DirectEncap bpf progs version mismatch, katran_de_ctl= "
            << currentVer << ", installed tc= " << *tcVer;
        return 1;
      }
    }
    XLOG(INFO) << "Katran DirectEncap bpf progs version matched: "
               << KDE_PROG_VERSION;
  }

  StatsPrinter printer(args.details, args.json, args.jsonDeltaSec, args.mode);
  for (int count = 0;; count++) {
    auto so = katran_tpr::KdeBpfUtil::aggregateSoStats(*soMap->map_);
    if (tcMap) {
      printer.printNewStats(
          so, katran_tpr::KdeBpfUtil::aggregateTcStats(*tcMap->map_));
    } else {
      printer.printNewStats(so);
    }
    if (args.json) {
      // raw counters need one sample, deltas need two jsonDeltaSec apart
      if (args.jsonDeltaSec == 0 || count > 0) {
        break;
      }
      sleep(args.jsonDeltaSec);
    } else {
      if (args.limit > 0 && count >= args.limit) {
        break;
      }
      sleep(1);
    }
  }

  if (!statusCheck) {
    return 0;
  }
  if (printer.totalErrors() > 0) {
    XLOG(ERR) << "Katran DirectEncap is installed but has errors";
    return 1;
  }
  XLOG(INFO) << "Katran DirectEncap is installed and running with no errors";
  return 0;
}

} // namespace katran_de::ctl
