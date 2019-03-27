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

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <iostream>

#include "katran/lib/BpfAdapter.h"

DEFINE_string(intf, "eth0", "default interface");
DEFINE_string(bpfprog, "xdp_root.o", "path to bpf program");
DEFINE_string(
    bpfpath,
    "/mnt/bpf/xdproot/xdproot_array",
    "path to where we want to pin root_array");
DEFINE_int32(xdp_flags, 0 , "xdp attachment flags");

int main(int argc, char** argv) {
  gflags::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  bool shared_map_found = false;
  katran::BpfAdapter adapter;
  int err;
  auto array_id = adapter.getPinnedBpfObject(FLAGS_bpfpath);
  if (array_id > 0) {
    LOG(INFO) << "using shared map for root array";
    adapter.updateSharedMap("root_array", array_id);
    shared_map_found = true;
  }
  err = adapter.loadBpfProg(FLAGS_bpfprog);
  if (err) {
    std::cout << "cant load bpf prog " << FLAGS_bpfprog << std::endl;
    return 1;
  }

  auto prog_fd = adapter.getProgFdByName("xdp-root");
  if (prog_fd < 0) {
    std::cout << "can't get prog_fd\n";
    return 1;
  }

  // attaching prog to eth0
  if (adapter.detachXdpProg(FLAGS_intf, FLAGS_xdp_flags)) {
    std::cout << "can't detach xdp prog\n";
    return 1;
  }

  if (adapter.attachXdpProg(prog_fd, FLAGS_intf, FLAGS_xdp_flags)) {
    std::cout << "cant attach bpf to interface " << FLAGS_intf << std::endl;
    return 1;
  }

  // map pinning
  auto root_array = adapter.getMapFdByName("root_array");
  if (root_array < 0) {
    std::cout << "can't get fd for vip_map\n";
    return 1;
  }
  if (!shared_map_found) {
    auto res = adapter.pinBpfObject(root_array, FLAGS_bpfpath);
    if (res < 0) {
      std::cout << "can't pin root array\n";
      return 1;
    }
  }

  return 0;
}
