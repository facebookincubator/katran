/* Copyright (C) 2018-present, Facebook, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <memory>
#include <vector>

#include <folly/Conv.h>
#include <folly/String.h>
#include <folly/init/Init.h>
#include <gflags/gflags.h>

#include "KatranSimpleClient.h"

using lb::katran::KatranSimpleClient;

// Define command line flags
DEFINE_bool(A, false, "Add new virtual service");
DEFINE_bool(E, false, "Edit existing virtual service");
DEFINE_bool(D, false, "Delete existing virtual service");
DEFINE_bool(a, false, "Add real server");
DEFINE_bool(e, false, "Edit real server");
DEFINE_bool(d, false, "Delete real server");
DEFINE_string(t, "", "Tcp service address. must be in format: <addr>:<port>");
DEFINE_string(u, "", "Udp service address. must be in format: <addr>:<port>");
DEFINE_string(r, "", "Address of the real server");
DEFINE_uint64(w, 1, "Weight (capacity) of real server");
DEFINE_bool(s, false, "Show stats/counters");
DEFINE_bool(sum, false, "Show summary stats");
DEFINE_bool(lru, false, "Show LRU related stats");
DEFINE_bool(icmp, false, "Show ICMP \"packet too big\"  related stats");
DEFINE_bool(l, false, "List configured services");
DEFINE_bool(C, false, "Clear all configs");
DEFINE_string(
    f, "",
    "change flags. Possible values: NO_SPORT, NO_LRU, QUIC_VIP, DPORT_HASH");
DEFINE_bool(unset, false, "Unset specified flags");
DEFINE_string(new_hc, "", "Address of new backend to healthcheck");
DEFINE_uint64(somark, 0, "Socket mark to specified backend");
DEFINE_bool(del_hc, false, "Delete backend w/ specified somark");
DEFINE_bool(list_hc, false, "List configured healthchecks");
DEFINE_bool(list_mac, false, "List configured mac address of default router");
DEFINE_string(change_mac, "",
              "Change configured mac address of default router");
DEFINE_string(quic_mapping, "",
              "mapping of real to connectionId. must be in <addr>=<id> format");
DEFINE_bool(list_qm, false, "List current quic's mappings");
DEFINE_bool(del_qm, false, "Delete instead of adding specified quic mapping");
// Address and port of katran thrift server
DEFINE_string(katran_server, "::1",
              "Address of katran thrift server. Default value is ::1");
DEFINE_int32(katran_port, 12307,
             "Port of katran thrift server. Default value is 12307");

int main(int argc, char **argv) {
  ::gflags::ParseCommandLineFlags(&argc, &argv, false);
  folly::init(&argc, &argv);
  // reassign flags for better readibility
  const bool addServiceFlag = FLAGS_A;
  const bool editServiceFlag = FLAGS_E;
  const bool delServiceFlag = FLAGS_D;
  const bool addServerFlag = FLAGS_a;
  const bool editServerFlag = FLAGS_e;
  const bool delServerFlag = FLAGS_d;
  const std::string tcpServiceFlag = FLAGS_t;
  const std::string udpServiceFlag = FLAGS_u;
  const std::string realServerFlag = FLAGS_r;
  const uint64_t realWeightFlag = FLAGS_w;
  const bool showStatsFlag = FLAGS_s;
  const bool showSumStatsFlag = FLAGS_sum;
  const bool showLruStatsFlag = FLAGS_lru;
  const bool showIcmpStatsFlag = FLAGS_icmp;
  const bool listServicesFlag = FLAGS_l;
  const bool clearAllFlag = FLAGS_C;
  const std::string changeFlags = FLAGS_f;

  FLAGS_logtostderr = 1;
  std::string service{""};
  int proto;
  if (tcpServiceFlag != "") {
    service = tcpServiceFlag;
    proto = IPPROTO_TCP;
  } else if (udpServiceFlag != "") {
    service = udpServiceFlag;
    proto = IPPROTO_UDP;
  }

  KatranSimpleClient client(FLAGS_katran_server, FLAGS_katran_port);
  if (FLAGS_change_mac != "") {
    client.changeMac(FLAGS_change_mac);
  } else if (FLAGS_list_mac) {
    client.getMac();
  } else if (addServiceFlag) {
    client.addOrModifyService(service, changeFlags, proto, false, true);
  } else if (listServicesFlag) {
    client.list("", proto);
  } else if (delServiceFlag) {
    client.delService(service, proto);
  } else if (editServiceFlag) {
    client.addOrModifyService(service, changeFlags, proto, true, !FLAGS_unset);
  } else if (addServerFlag || editServerFlag) {
    client.updateServerForVip(service, proto, realServerFlag, realWeightFlag,
                              false);
  } else if (delServerFlag) {
    client.updateServerForVip(service, proto, realServerFlag, realWeightFlag,
                              true);
  } else if (FLAGS_del_qm) {
    if (FLAGS_quic_mapping == "") {
      LOG(FATAL) << "quic_mapping is not specified.";
      exit(1);
    }
    client.modifyQuicMappings(FLAGS_quic_mapping, true);
  } else if (FLAGS_quic_mapping != "") {
    client.modifyQuicMappings(FLAGS_quic_mapping, false);
  } else if (FLAGS_list_qm) {
    client.listQm();
  } else if (clearAllFlag) {
    client.clearAll();
  } else if (FLAGS_new_hc != "") {
    client.addHc(FLAGS_new_hc, FLAGS_somark);
  } else if (FLAGS_del_hc) {
    client.delHc(FLAGS_somark);
  } else if (FLAGS_list_hc) {
    client.listHc();
  } else if (showStatsFlag) {
    if (showSumStatsFlag) {
      client.showSumStats();
    } else if (showLruStatsFlag) {
      client.showLruStats();
    } else if (showIcmpStatsFlag) {
      client.showIcmpStats();
    } else {
      client.showPerVipStats();
    }
  }
  VLOG(3) << "KatranSimpleClient exiting...";
  return 0;
}
