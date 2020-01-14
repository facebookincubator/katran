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

#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace katran {

namespace {
constexpr uint32_t kDefaultKatranPos = 2;
constexpr uint32_t kDefaultMaxVips = 512;
constexpr uint32_t kDefaultMaxReals = 4096;
constexpr uint32_t kDefaultPriority = 2307;
constexpr uint32_t kLbDefaultChRingSize = 65537;
constexpr uint32_t kDefaultMaxLpmSrcSize = 3000000;
constexpr uint32_t kDefaultMaxDecapDstSize = 6;
constexpr uint32_t kDefaultNumOfPages = 2;
constexpr uint32_t kDefaultMonitorQueueSize = 4096;
constexpr uint32_t kDefaultMonitorPcktLimit = 0;
constexpr uint32_t kDefaultMonitorSnapLen = 128;
constexpr uint32_t kDefaultMonitorMaxEvents = 4;
constexpr unsigned int kDefaultLruSize = 8000000;
constexpr uint32_t kNoFlags = 0;
std::string kNoExternalMap = "";
std::string kDefaultHcInterface = "";
std::string kAddressNotSpecified = "";
} // namespace

/**
 * struct with meta info for real
 */
struct RealMeta {
  /**
   *vip's number
   */
  uint32_t num;

  /**
   * one real could be used by multiple vips
   * we will delete real (recycle it's num),
   * only when refcount would be equal to zero
   */
  uint32_t refCount;
};

/**
 * information about new real
 */

struct NewReal {
  std::string address;
  uint32_t weight;
};

/**
 * information about quic's real
 */
struct QuicReal {
  std::string address;
  uint32_t id;
};

/**
 * types of address
 */
enum class AddressType {
  INVALID,
  HOST,
  NETWORK,
};

/**
 * types of monitoring
 */
enum class PcapStorageFormat {
  FILE,
  IOBUF,
};

/**
 * @param uint32_t nCpus number of cpus
 * @param uint32_t pages number of pages for even pipe shared memory
 * @param int mapFd descriptor of event pipe map
 * @param uint32_t queueSize size of mpmc queue between readers and pcap writer
 * @param uint32_t maxPackets to capture, 0 - no limit
 * @param uint32_t snapLen maximum number of bytes from packet to write.
 * @param uint32_t maxEvents maximum supported events/pcap writers
 * @param std::string path where pcap outputs are going to be stored
 *
 * katran monitoring config. being used if katran's bpf code was build w/
 * introspection enabled (-DKATRAN_INTROSPECTION)
 */
struct KatranMonitorConfig {
  uint32_t nCpus;
  uint32_t pages{kDefaultNumOfPages};
  int mapFd;
  uint32_t queueSize{kDefaultMonitorQueueSize};
  uint32_t pcktLimit{kDefaultMonitorPcktLimit};
  uint32_t snapLen{kDefaultMonitorSnapLen};
  uint32_t maxEvents{kDefaultMonitorMaxEvents};
  std::string path{"/tmp/katran_pcap"};
  PcapStorageFormat storage{PcapStorageFormat::FILE};
  uint32_t bufferSize{0};
};

/**
 * struct which contains all configurations for KatranLB
 * @param string mainInterface name where to attach bpf prog (e.g eth0)
 * @param string v4TunInterface name for ipip encap (for healtchecks)
 * @param string v6TunInterface name for ip(6)ip6 encap (for healthchecks)
 * @param string balancerProgPath path to bpf prog for balancer
 * @param string healthcheckingProgPath path to bpf prog for healthchecking
 * @param std::vector<uint8_t> defaultMac mac address of default router
 * @param uint32_t tc priority of healtchecking task
 * @param string rootMapPath path to pinned map from root xdp prog
 * @param rootMapPos position inside rootMap
 * @param bool enableHc flag, is set - we will load healthchecking bpf prog
 * @param uint32_t maxVips maximum allowed vips to configure
 * @param uint32_t maxReals maximum allowed reals to configure
 * @param uint32_t chRingSize size of ch ring for each real
 * @param bool testing flag, if true - don't program forwarding
 * @param uint64_t LruSize size of connection table
 * @param std::vector<int32_t> forwardingCores responsible for forwarding
 * @param std::vector<int32_t> numaNodes mapping of cores to NUMA nodes
 * @param uint32_t maxLpmSrcSize maximum size of map for src based routing
 * @param uint32_t maxDecapDst maximum number of destinations for inline decap
 * @param std::string hcInterface interface where we want to attach hc bpf prog
 * @param KatranMonitorConfig monitorConfig for katran introspection
 * @param memlockUnlimited should katran set memlock to unlimited by default
 * @param katranSrcV4 string ipv4 source address for GUE packets
 * @param katranSrcV6 string ipv6 source address for GUE packets
 * @param std::vector<uint8_t> localMac mac address of local server
 *
 * note about rootMapPath and rootMapPos:
 * katran has two modes of operation.
 * the first one is "standalone":
 * when it register itself as one and only xdp prog; this is
 * default. for this mode to work rootMapPath must be equal to "".
 * and we dont evaluate rootMapPos (so it could be any value).
 *
 * the second mode of operation - "shared" -
 * is when we have root xdp prog: which is
 * just doing bpf_tail_call for other xdp's progs, which must registers
 * (put their fd's into predifiened position inside rootMap).
 * in this case rootMapPath must be path to "pinned" map, which has been
 * used by root xdp prog, and rootMapPos is a position (index) of
 * katran's fd inside this map.
 *
 * by default, if hcInterface is not specified we are going to attach
 * healthchecking bpf program to the mainInterfaces
 */
struct KatranConfig {
  std::string mainInterface;
  std::string v4TunInterface;
  std::string v6TunInterface;
  std::string balancerProgPath;
  std::string healthcheckingProgPath;
  std::vector<uint8_t> defaultMac;
  uint32_t priority = kDefaultPriority;
  std::string rootMapPath = kNoExternalMap;
  uint32_t rootMapPos = kDefaultKatranPos;
  bool enableHc = true;
  uint32_t maxVips = kDefaultMaxVips;
  uint32_t maxReals = kDefaultMaxReals;
  uint32_t chRingSize = kLbDefaultChRingSize;
  bool testing = false;
  uint64_t LruSize = kDefaultLruSize;
  std::vector<int32_t> forwardingCores;
  std::vector<int32_t> numaNodes;
  uint32_t maxLpmSrcSize = kDefaultMaxLpmSrcSize;
  uint32_t maxDecapDst = kDefaultMaxDecapDstSize;
  std::string hcInterface = kDefaultHcInterface;
  uint32_t xdpAttachFlags = kNoFlags;
  struct KatranMonitorConfig monitorConfig;
  bool memlockUnlimited = true;
  std::string katranSrcV4 = kAddressNotSpecified;
  std::string katranSrcV6 = kAddressNotSpecified;
  std::vector<uint8_t> localMac;
};

/**
 * @param uint32_t limit of packet writer. how many packets we would write
 * before we stop
 * @param uint32_ amount of packets which has been written so far
 *
 * struct which contains stats from katran monitor
 */
struct KatranMonitorStats {
  uint32_t limit{0};
  uint32_t amount{0};
  uint32_t bufferFull{0};
};

/**
 * @param uint64_t bpfFailedCalls number of failed syscalls
 * @param uint64_t addrValidationFailed times provided ipaddress was invalid
 *
 * generic userspace related stats to track internals of katran library
 * such as number of failed bpf syscalls (could happens if we are trying to add
 * to many vips etc)
 */
struct KatranLbStats {
  uint64_t bpfFailedCalls{0};
  uint64_t addrValidationFailed{0};
};

/**
 * @param uint64_t packetsProcessed number of packets processed for the
 * healthcheck prog
 * @param uint64_t packetsDropped total number of packets dropped
 * @param uint64_t packetsSkipped total number of packets without action taken
 * @param uint64_t packetsTooBig total number of packets larger than
 * prespecified max size for a packet
 *
 * struct to record packet level counters for events in health-check program
 * NOTE: this must be kept in sync with 'hc_stats' in healthchecking_ipip.c
 */
struct HealthCheckProgStats {
  uint64_t packetsProcessed{0};
  uint64_t packetsDropped{0};
  uint64_t packetsSkipped{0};
  uint64_t packetsTooBig{0};
};

/**
 * @param srcRouting flag which indicates that source based routing feature has
 * been enabled/compiled in bpf forwarding plane
 * @param inlineDecap flag which indicates that inline decapsulation feature has
 * been enabled/compiled in bpf forwarding plane
 * @param introspection flag which indicates that katran introspection is
 * enabled
 * @param gueEncap flag which indicates that GUE instead of IPIP should be used
 * @param directHealthchecking flag which inidcates that hc encapsulation would
 * be directly created instead of using tunnel interfaces
 */
struct KatranFeatures {
  bool srcRouting{false};
  bool inlineDecap{false};
  bool introspection{false};
  bool gueEncap{false};
  bool directHealthchecking{false};
};

/**
 * class which identifies vip
 */

class VipKey {
 public:
  std::string address;
  uint16_t port;
  uint8_t proto;

  bool operator==(const VipKey& other) const {
    return (
        address == other.address && port == other.port && proto == other.proto);
  };
};

struct VipKeyHasher {
  std::size_t operator()(const VipKey& k) const {
    return ((std::hash<std::string>()(k.address) ^
             (std::hash<uint16_t>()(k.port) << 1)) >>
            1) ^
        (std::hash<uint8_t>()(k.proto) << 1);
  };
};

} // namespace katran
