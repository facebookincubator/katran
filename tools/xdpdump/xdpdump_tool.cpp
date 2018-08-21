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

#include <cstring>
#include <folly/io/async/EventBaseManager.h>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <iostream>

#include "katran/lib/IpHelpers.h"

#include "PcapWriter.h"
#include "XdpDump.h"
#include "XdpDumpStructs.h"

DEFINE_string(src, "", "source ip address");
DEFINE_string(dst, "", "destination ip address");
DEFINE_int32(sport, 0, "source port");
DEFINE_int32(dport, 0, "destination port");
DEFINE_int32(proto, 0, "protocol to match");
DEFINE_int32(offset, 0, "offset for byte matching");
DEFINE_int32(offset_len, 0, "length fot the bytematching; up to 4");
DEFINE_int32(cpu, -1, "cpu to take dump from");
DEFINE_int64(pattern, 0, "pattern for bytematching; up to 4bytes");
DEFINE_string(map_path, "/sys/fs/bpf/jmp_eth0", "path to root jump array");
DEFINE_string(pcap_path, "", "path to pcap file");
DEFINE_int32(packet_limit, 0,
             "max number of packets to be written in pcap file");
DEFINE_bool(clear, false, "remove xdpdump from shared array");
DEFINE_bool(mute, false, "switch off output of received packets");
DEFINE_int32(snaplen, 0,
             "max length of the packet that will be captured "
             "(set 0 to capture whole packet)");
DEFINE_int32(bpf_mmap_pages, 2,
             "How many pages should be mmap-ed to the perf event for each CPU. "
             "It must be a power of 2.");
DEFINE_int32(duration_ms, -1, "how long to take a capture");

using PcapWriter = xdpdump::PcapWriter;

int main(int argc, char **argv) {
  gflags::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  xdpdump::XdpDumpFilter filter = {};
  // flags to filter parsing
  if (!FLAGS_src.empty()) {
    filter.flags |= xdpdump::kSrcSet;
    auto src_addr = katran::IpHelpers::parseAddrToBe(FLAGS_src);
    if (src_addr.flags > 0) {
      // ipv6
      std::memcpy(&filter.srcv6, &src_addr.v6daddr, 16);
      filter.ipv6 = true;
    } else {
      filter.src = src_addr.daddr;
    }
  }
  if (!FLAGS_dst.empty()) {
    filter.flags |= xdpdump::kDstSet;
    auto dst_addr = katran::IpHelpers::parseAddrToBe(FLAGS_dst);
    if (dst_addr.flags > 0) {
      // ipv6
      if (!FLAGS_src.empty() && !filter.ipv6) {
        // src is specified and it's ipv4
        std::cout << "v4 src and v6 dst is not supported\n";
        return -1;
      }
      std::memcpy(&filter.dstv6, &dst_addr.v6daddr, 16);
    } else {
      if (filter.ipv6) {
        // src is specified and it's ipv6
        std::cout << "v6 src and v4 dst is not supported\n";
        return -1;
      }
      filter.dst = dst_addr.daddr;
    }
  }
  if (FLAGS_snaplen < 0 || FLAGS_snaplen > 0xFFFF) {
    std::cout << "snaplen should be between 0 and 65535."
              << " Set to 0 to capture whole packet." << std::endl;
    return -1;
  }

  if (FLAGS_sport != 0) {
    filter.flags |= xdpdump::kSportSet;
    filter.sport = (uint16_t)FLAGS_sport;
  }
  if (FLAGS_dport != 0) {
    filter.flags |= xdpdump::kDportSet;
    filter.dport = (uint16_t)FLAGS_dport;
  }
  if (FLAGS_proto != 0) {
    filter.flags |= xdpdump::kProtoSet;
    filter.proto = (uint8_t)FLAGS_proto;
  }

  filter.offset = (uint16_t)FLAGS_offset;
  filter.offset_len = (uint16_t)FLAGS_offset_len;
  filter.pattern = (uint32_t)FLAGS_pattern;
  filter.map_path = FLAGS_map_path;
  filter.mute = FLAGS_mute;
  filter.cpu = FLAGS_cpu;
  filter.pages = FLAGS_bpf_mmap_pages;
  // end of parsing

  std::shared_ptr<PcapWriter> pcapWriter;
  if (!FLAGS_pcap_path.empty()) {
    auto fileWriter = std::make_shared<PcapWriter::FileWriter>(FLAGS_pcap_path);
    pcapWriter = std::make_shared<PcapWriter>(fileWriter, FLAGS_packet_limit,
                                              FLAGS_snaplen);
  }

  auto evb = folly::EventBaseManager::get()->getEventBase();
  xdpdump::XdpDump xdpdump(evb, filter, pcapWriter);

  try {
    if (FLAGS_clear) {
      xdpdump.clear();
    } else {
      // if (FLAGS_duration_ms.count() != 0) {
      //  xdpdump.scheduleTimeout(FLAGS_duration_ms);
      //}
      xdpdump.run();
    }
  } catch (const std::runtime_error &e) {
    LOG(ERROR) << "XdpDump error: " << e.what();
  }
  return 0;
}
