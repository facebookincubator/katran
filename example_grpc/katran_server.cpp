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

#include <iostream>
#include <memory>
#include <signal.h>
#include <string>
#include <vector>
#include <thread>

#include <folly/Conv.h>
#include <folly/init/Init.h>
#include <folly/io/async/EventBase.h>
#include <folly/String.h>
#include <gflags/gflags.h>
#include <grpc++/grpc++.h>

#include "KatranGrpcService.h"
#include "GrpcSignalHandler.h"
#include "katran/lib/MacHelpers.h"


using grpc::Server;
using grpc::ServerBuilder;

DEFINE_string(server, "0.0.0.0:50051", "Service server:port");
DEFINE_string(intf, "eth0", "main interface");
DEFINE_string(hc_intf, "", "interface for healthchecking");
DEFINE_string(ipip_intf, "ipip0", "ipip (v4) encap interface");
DEFINE_string(ipip6_intf, "ipip60", "ip(6)ip6 (v6) encap interface");
DEFINE_string(balancer_prog, "./balancer_kern.o", "path to balancer bpf prog");
DEFINE_string(
  healthchecker_prog,
  "./healthchecking_ipip.o",
  "path to healthchecking bpf prog");
DEFINE_string(
  default_mac,
  "00:00:00:00:00:01",
  "mac address of default router. must be in fomrat: xx:xx:xx:xx:xx:xx");
DEFINE_int32(priority, 2307, "tc's priority for bpf progs");
DEFINE_string(map_path, "", "path to pinned map from root xdp prog."
  " default path forces to work in standalone mode");
DEFINE_int32(prog_pos, 2, "katran's position inside root xdp array");
DEFINE_bool(hc_forwarding, true, "turn on forwarding path for healthchecks");
DEFINE_int32(shutdown_delay, 10000, "shutdown delay in milliseconds");
DEFINE_int64(lru_size, 8000000, "size of LRU table");
DEFINE_string(forwarding_cores, "", "coma separed list of forwarding cores");
DEFINE_string(
  numa_nodes,
  "",
  "coma separed list of numa nodes to forwarding cores mapping");

// routine which parses coma separated string of numbers
// (e.g. "1,2,3,4,10,11,12,13") to vector of int32_t
// will throw on failure.
std::vector<int32_t> parseIntLine(const std::string& line) {
  std::vector<int32_t> nums;
  if (!line.empty()) {
    std::vector<std::string> splitedLine;
    folly::split(",", line, splitedLine);
    for (const auto& num_str: splitedLine) {
      auto num = folly::to<int32_t>(num_str);
      nums.push_back(num);
    }
  }
  return nums;
}


void RunServer(
    katran::KatranConfig& config,
    int32_t delay,
    std::shared_ptr<folly::EventBase> evb) {
  std::string server_address(FLAGS_server);
  lb::katran::KatranGrpcService service(config);

  ServerBuilder builder;
  // Listen on the given address without any authentication mechanism.
  builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
  // Register "service" as the instance through which we'll communicate with
  // clients. In this case it corresponds to an *synchronous* service.
  builder.RegisterService(&service);
  // Finally assemble the server.
  std::unique_ptr<Server> server(builder.BuildAndStart());
  std::cout << "Server listening on " << server_address << std::endl;
  lb::katran::GrpcSignalHandler grpcSigHandler(evb, server.get(), delay);
  grpcSigHandler.registerSignalHandler(SIGINT);
  grpcSigHandler.registerSignalHandler(SIGTERM);
  // Wait for the server to shutdown. Note that some other thread must be
  // responsible for shutting down the server for this call to ever return.
  server->Wait();
}

int main(int argc, char** argv) {
  folly::init(&argc, &argv);
  FLAGS_logtostderr = 1;

  auto forwardingCores = parseIntLine(FLAGS_forwarding_cores);
  VLOG(2) << "size of forwarding cores vector is " << forwardingCores.size();
  auto numaNodes = parseIntLine(FLAGS_numa_nodes);
  VLOG(2) << "size of numa nodes vector is " << numaNodes.size();

  katran::KatranConfig config = {
    .mainInterface = FLAGS_intf,
    .v4TunInterface = FLAGS_ipip_intf,
    .v6TunInterface = FLAGS_ipip6_intf,
    .balancerProgPath = FLAGS_balancer_prog,
    .healthcheckingProgPath = FLAGS_healthchecker_prog,
    .defaultMac = katran::convertMacToUint(FLAGS_default_mac),
    .priority = static_cast<uint32_t>(FLAGS_priority),
    .rootMapPath = FLAGS_map_path,
    .rootMapPos = static_cast<uint32_t>(FLAGS_prog_pos),
    .enableHc = FLAGS_hc_forwarding,
  };
  config.LruSize = static_cast<uint64_t>(FLAGS_lru_size);
  config.forwardingCores = forwardingCores;
  config.numaNodes = numaNodes;
  config.hcInterface = FLAGS_hc_intf;

  auto evb = std::make_shared<folly::EventBase>();
  std::thread t1([evb](){
    evb->loopForever();
  });
  t1.detach();

  RunServer(config, FLAGS_shutdown_delay, evb);
  return 0;
}
