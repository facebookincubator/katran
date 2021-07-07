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

#include "KatranLb.h"

#include <algorithm>
#include <array>
#include <iterator>
#include <stdexcept>

#include <folly/Format.h>
#include <folly/lang/Bits.h>
#include <glog/logging.h>

#include "katran/lib/KatranMonitor.h"

namespace katran {

namespace {
constexpr uint8_t V6DADDR = 1;
constexpr int kDeleteXdpProg = -1;
constexpr int kMacBytes = 6;
constexpr int kCtlMapSize = 16;
constexpr int kLruPrototypePos = 0;
constexpr int kMaxForwardingCores = 128;
constexpr int kFirstElem = 0;
constexpr int kError = -1;
constexpr uint32_t kMaxQuicId = 0x00fffffe; // 2^24-1
constexpr uint32_t kDefaultStatsIndex = 0;
constexpr folly::StringPiece kEmptyString = "";
constexpr uint32_t kSrcV4Pos = 0;
constexpr uint32_t kSrcV6Pos = 1;
constexpr uint32_t kRecirculationIndex = 0;
constexpr uint32_t kHcSrcMacPos = 0;
constexpr uint32_t kHcDstMacPos = 1;
constexpr folly::StringPiece kFlowDebugParentMapName = "flow_debug_maps";
constexpr folly::StringPiece kFlowDebugCpuLruName = "flow_debug_lru";
using EventId = monitoring::EventId;
} // namespace

KatranLb::KatranLb(const KatranConfig& config)
    : config_(config),
      bpfAdapter_(config.memlockUnlimited),
      ctlValues_(kCtlMapSize),
      standalone_(true),
      forwardingCores_(config.forwardingCores),
      numaNodes_(config.numaNodes),
      lruMapsFd_(kMaxForwardingCores),
      flowDebugMapsFd_(kMaxForwardingCores) {
  for (uint32_t i = 0; i < config_.maxVips; i++) {
    vipNums_.push_back(i);
  }

  for (uint32_t i = 0; i < config_.maxReals; i++) {
    realNums_.push_back(i);
  }

  if (!config_.rootMapPath.empty()) {
    standalone_ = false;
  }

  if (config_.hcInterface.empty()) {
    config_.hcInterface = config_.mainInterface;
  }

  if (!config_.testing) {
    ctl_value ctl;
    int res;

    // populating ctl vector
    if (config_.defaultMac.size() != 6) {
      throw std::invalid_argument("mac's size is not equal to six byte");
    }
    for (int i = 0; i < 6; i++) {
      ctl.mac[i] = config_.defaultMac[i];
    }
    ctlValues_[kMacAddrPos] = ctl;

    if (config_.enableHc) {
      res = bpfAdapter_.getInterfaceIndex(config_.hcInterface);
      if (res == 0) {
        throw std::invalid_argument(folly::sformat(
            "can't resolve ifindex for healthcheck interface, error: {}",
            folly::errnoStr(errno)));
      }
      ctl.ifindex = res;
      ctlValues_[kHcIntfPos] = ctl;
      if (config_.tunnelBasedHCEncap) {
        res = bpfAdapter_.getInterfaceIndex(config_.v4TunInterface);
        if (!res) {
          throw std::invalid_argument(folly::sformat(
              "can't resolve ifindex for v4tunel intf, error: {}",
              folly::errnoStr(errno)));
        }
        ctl.ifindex = res;
        ctlValues_[kIpv4TunPos] = ctl;

        res = bpfAdapter_.getInterfaceIndex(config_.v6TunInterface);
        if (!res) {
          throw std::invalid_argument(folly::sformat(
              "can't resolve ifindex for v6tunel intf, error: {}",
              folly::errnoStr(errno)));
        }
        ctl.ifindex = res;
        ctlValues_[kIpv6TunPos] = ctl;
      }
    }

    res = bpfAdapter_.getInterfaceIndex(config_.mainInterface);
    if (!res) {
      throw std::invalid_argument(folly::sformat(
          "can't resolve ifindex for main intf, error: {}",
          folly::errnoStr(errno)));
    }
    ctl.ifindex = res;
    ctlValues_[kMainIntfPos] = ctl;
  }
}

KatranLb::~KatranLb() {
  if (!config_.testing && progsAttached_) {
    int res;
    auto mainIfindex = ctlValues_[kMainIntfPos].ifindex;
    auto hcIfindex = ctlValues_[kHcIntfPos].ifindex;
    if (standalone_) {
      res = bpfAdapter_.detachXdpProg(mainIfindex, config_.xdpAttachFlags);
    } else {
      res = bpfAdapter_.bpfMapDeleteElement(rootMapFd_, &config_.rootMapPos);
    }
    if (res != 0) {
      LOG(INFO) << folly::sformat(
          "wasn't able to delete main bpf prog, error: {}",
          folly::errnoStr(errno));
    }
    if (config_.enableHc) {
      res = bpfAdapter_.deleteTcBpfFilter(
          getHealthcheckerProgFd(),
          hcIfindex,
          "katran-healthchecker",
          config_.priority,
          TC_EGRESS);
      if (res != 0) {
        LOG(INFO) << folly::sformat(
            "wasn't able to delete hc bpf prog, error: {}",
            folly::errnoStr(errno));
      }
    }
  }
}

AddressType KatranLb::validateAddress(
    const std::string& addr,
    bool allowNetAddr) {
  if (!folly::IPAddress::validate(addr)) {
    if (allowNetAddr && (features_.srcRouting || config_.testing)) {
      auto ret = folly::IPAddress::tryCreateNetwork(addr);
      if (ret.hasValue()) {
        return AddressType::NETWORK;
      }
    }
    lbStats_.addrValidationFailed++;
    LOG(ERROR) << "Invalid address: " << addr;
    return AddressType::INVALID;
  }
  return AddressType::HOST;
}

void KatranLb::initialSanityChecking(bool flowDebug) {
  int res;

  std::vector<std::string> maps;

  if (!config_.disableForwarding) {
    maps.push_back("ctl_array");
    maps.push_back("vip_map");
    maps.push_back("ch_rings");
    maps.push_back("reals");
    maps.push_back("stats");
    maps.push_back("lru_mapping");
    maps.push_back("server_id_map");

    if (flowDebug) {
      maps.push_back(kFlowDebugParentMapName.data());
    }

    res = getKatranProgFd();
    if (res < 0) {
      throw std::invalid_argument(folly::sformat(
          "can't get fd for prog: {}, error: {}",
          kBalancerProgName,
          folly::errnoStr(errno)));
    }
  }

  if (config_.enableHc) {
    res = getHealthcheckerProgFd();
    if (res < 0) {
      throw std::invalid_argument(folly::sformat(
          "can't get fd for prog: {}, error: {}",
          kHealthcheckerProgName,
          folly::errnoStr(errno)));
    }
    maps.push_back("hc_ctrl_map");
    maps.push_back("hc_reals_map");
    maps.push_back("hc_stats_map");
  }

  // some sanity checking. we will check that all maps exists, so in later
  // code we wouldn't check if their fd != -1
  // names of the maps must be the same as in bpf code.
  for (auto& map : maps) {
    res = bpfAdapter_.getMapFdByName(map);
    if (res < 0) {
      VLOG(4) << "missing map: " << map;
      throw std::invalid_argument(
          folly::sformat("map not found, error: {}", folly::errnoStr(errno)));
    }
  }
}

int KatranLb::createLruMap(int size, int flags, int numaNode) {
  return bpfAdapter_.createNamedBpfMap(
      "katran_lru",
      kBpfMapTypeLruHash,
      sizeof(struct flow_key),
      sizeof(struct real_pos_lru),
      size,
      flags,
      numaNode);
}

void KatranLb::initFlowDebugMapForCore(int core, int size, int flags, int numaNode) {
  int lru_fd;
  VLOG(3) << "Creating flow debug lru for core " << core;
  lru_fd = bpfAdapter_.createNamedBpfMap(
      kFlowDebugCpuLruName.data(),
      kBpfMapTypeLruHash,
      sizeof(struct flow_key),
      sizeof(struct flow_debug_info),
      size,
      flags,
      numaNode);
  if (lru_fd < 0) {
    LOG(ERROR) << "can't create lru for core: " << core;
    throw std::runtime_error(folly::sformat(
        "can't create LRU for forwarding core, error: {}",
        folly::errnoStr(errno)));
    }
  VLOG(3) << "Created flow debug lru for core " << core;
  flowDebugMapsFd_[core] = lru_fd;
}

void KatranLb::initFlowDebugPrototypeMap() {
  int flow_proto_fd, res;
  if (forwardingCores_.size() != 0) {
    flow_proto_fd = flowDebugMapsFd_[forwardingCores_[kFirstElem]];
  } else {
    VLOG(3) << "Creating generic flow debug lru";
    flow_proto_fd = bpfAdapter_.createNamedBpfMap(
      kFlowDebugCpuLruName.data(),
      kBpfMapTypeLruHash,
      sizeof(struct flow_key),
      sizeof(struct flow_debug_info),
      katran::kFallbackLruSize,
      kMapNoFlags,
      kNoNuma);
  }
  if (flow_proto_fd < 0) {
    throw std::runtime_error(folly::sformat(
      "can't create LRU prototype, error: {}",
      folly::errnoStr(errno)));
  }
  res = bpfAdapter_.setInnerMapPrototype(kFlowDebugParentMapName.data(), flow_proto_fd);
  if (res < 0) {
    throw std::runtime_error(folly::sformat(
        "can't update inner_maps_fds w/ prototype for main lru, error: {}",
        folly::errnoStr(errno)));
  }
  VLOG(3) << "Created flow map proto";
}

void KatranLb::attachFlowDebugLru(int core) {
  int map_fd, res, key;
  key = core;
  map_fd = flowDebugMapsFd_[core];
  if (map_fd < 0) {
    throw std::runtime_error(folly::sformat(
      "Invalid FD found for core {}: {}", core, map_fd));
  }
  res = bpfAdapter_.bpfUpdateMap(
    bpfAdapter_.getMapFdByName(kFlowDebugParentMapName.data()), &key, &map_fd);
  if (res < 0) {
    throw std::runtime_error(folly::sformat(
      "can't attach lru to forwarding core, error: {}",
      folly::errnoStr(errno)));
  }
  VLOG(3) << "Set cpu core " << core << "flow map id to " << map_fd;
}

void KatranLb::initLrus(bool flowDebug) {
  bool forwarding_cores_specified{false};
  bool numa_mapping_specified{false};
  int lru_map_flags = 0;
  int lru_proto_fd;
  int res;
  if (forwardingCores_.size() != 0) {
    if (numaNodes_.size() != 0) {
      if (numaNodes_.size() != forwardingCores_.size()) {
        throw std::runtime_error(
            "numaNodes size mut be equal to forwardingCores");
      }
      numa_mapping_specified = true;
    }
    int lru_fd, numa_node;
    auto per_core_lru_size = config_.LruSize / forwardingCores_.size();
    VLOG(2) << "per core lru size: " << per_core_lru_size;
    for (int i = 0; i < forwardingCores_.size(); i++) {
      auto core = forwardingCores_[i];
      if ((core > kMaxForwardingCores) || core < 0) {
        LOG(FATAL) << "got core# " << core
                   << " which is not in supported range: [ 0: "
                   << kMaxForwardingCores << " ]";
        throw std::runtime_error("unsuported number of forwarding cores");
      }
      if (numa_mapping_specified) {
        numa_node = numaNodes_[i];
        lru_map_flags |= kMapNumaNode;
      } else {
        numa_node = kNoNuma;
      }
      lru_fd = createLruMap(per_core_lru_size, lru_map_flags, numa_node);
      if (lru_fd < 0) {
        LOG(FATAL) << "can't creat lru for core: " << core;
        throw std::runtime_error(folly::sformat(
            "can't create LRU for forwarding core, error: {}",
            folly::errnoStr(errno)));
      }
      lruMapsFd_[core] = lru_fd;
      if (flowDebug) {
        initFlowDebugMapForCore(core, per_core_lru_size, lru_map_flags, numa_node);
      }
    }
    forwarding_cores_specified = true;
  }

  if (forwarding_cores_specified) {
    // creating prototype for main LRU's map in map
    // as we know that forwardingCores_ at least has one element
    // we are going to use the first one as a key to find fd of
    // already created LRU
    lru_proto_fd = lruMapsFd_[forwardingCores_[kFirstElem]];
  } else {
    // creating prototype for LRU's map-in-map. this code path would be hit
    // only during unit tests, where we dont specify forwarding cores
    lru_proto_fd = createLruMap();

    if (lru_proto_fd < 0) {
      throw std::runtime_error("can't create prototype map for test lru");
    }
  }
  res = bpfAdapter_.setInnerMapPrototype("lru_mapping", lru_proto_fd);
  if (res < 0) {
    throw std::runtime_error(folly::sformat(
        "can't update inner_maps_fds w/ prototype for main lru, error: {}",
        folly::errnoStr(errno)));
  }
}

void KatranLb::attachLrus(bool flowDebug) {
  if (!progsLoaded_) {
    throw std::runtime_error("can't attach lru when bpf progs are not loaded");
  }
  int map_fd, res, key;
  for (const auto& core : forwardingCores_) {
    key = core;
    map_fd = lruMapsFd_[core];
    res = bpfAdapter_.bpfUpdateMap(
        bpfAdapter_.getMapFdByName("lru_mapping"), &key, &map_fd);
    if (res < 0) {
      throw std::runtime_error(folly::sformat(
          "can't attach lru to forwarding core, error: {}",
          folly::errnoStr(errno)));
    }
    if (flowDebug) {
      attachFlowDebugLru(core);
    }
  }
}

void KatranLb::setupGueEnvironment() {
  if (config_.katranSrcV4.empty() && config_.katranSrcV6.empty()) {
    throw std::runtime_error(
        "No source address provided to use as source GUE encapsulation");
  }
  if (!config_.katranSrcV4.empty()) {
    auto srcv4 =
        IpHelpers::parseAddrToBe(folly::IPAddress(config_.katranSrcV4));
    uint32_t key = kSrcV4Pos;
    auto res = bpfAdapter_.bpfUpdateMap(
        bpfAdapter_.getMapFdByName("pckt_srcs"), &key, &srcv4);
    if (res < 0) {
      throw std::runtime_error("can not update src v4 address for GUE packet");
    }
  } else {
    LOG(ERROR) << "Empty IPV4 address provided to use as source in GUE encap";
  }
  if (!config_.katranSrcV6.empty()) {
    auto srcv6 =
        IpHelpers::parseAddrToBe(folly::IPAddress(config_.katranSrcV6));
    auto key = kSrcV6Pos;
    auto res = bpfAdapter_.bpfUpdateMap(
        bpfAdapter_.getMapFdByName("pckt_srcs"), &key, &srcv6);
    if (res < 0) {
      throw std::runtime_error("can not update src v6 address for GUE packet");
    }
  } else {
    LOG(ERROR) << "Empty IPV6 address provided to use as source in GUE encap";
  }
}

void KatranLb::setupHcEnvironment() {
  auto map_fd = bpfAdapter_.getMapFdByName("hc_pckt_srcs_map");
  if (config_.katranSrcV4.empty() && config_.katranSrcV6.empty()) {
    throw std::runtime_error(
        "No source address provided for direct healthchecking");
  }
  if (!config_.katranSrcV4.empty()) {
    auto srcv4 =
        IpHelpers::parseAddrToBe(folly::IPAddress(config_.katranSrcV4));
    uint32_t key = kSrcV4Pos;
    auto res = bpfAdapter_.bpfUpdateMap(map_fd, &key, &srcv4);
    if (res < 0) {
      throw std::runtime_error(
          "can not update src v4 address for direct healthchecking");
    }
  } else {
    LOG(ERROR) << "Empty IPV4 address provided to use as source in healthcheck";
  }
  if (!config_.katranSrcV6.empty()) {
    auto srcv6 =
        IpHelpers::parseAddrToBe(folly::IPAddress(config_.katranSrcV6));
    auto key = kSrcV6Pos;
    auto res = bpfAdapter_.bpfUpdateMap(map_fd, &key, &srcv6);
    if (res < 0) {
      throw std::runtime_error(
          "can not update src v6 address for direct healthchecking");
    }
  } else {
    LOG(ERROR) << "Empty IPV6 address provided to use as source in healthcheck";
  }

  std::array<struct hc_mac, 2> macs;
  // populating mac addresses for healthchecking
  if (config_.localMac.size() != 6) {
    throw std::invalid_argument("src mac's size is not equal to six byte");
  }
  for (int i = 0; i < 6; i++) {
    macs[kHcSrcMacPos].mac[i] = config_.localMac[i];
    macs[kHcDstMacPos].mac[i] = config_.defaultMac[i];
  }
  for (auto position : {kHcSrcMacPos, kHcDstMacPos}) {
    auto res = bpfAdapter_.bpfUpdateMap(
        bpfAdapter_.getMapFdByName("hc_pckt_macs"), &position, &macs[position]);
    if (res < 0) {
      throw std::runtime_error("can not update healthchecks mac address");
    }
  }
}

bool KatranLb::addSrcIpForPcktEncap(const folly::IPAddress& src) {
  auto srcBe = IpHelpers::parseAddrToBe(src);
  uint32_t key = src.isV4() ? kSrcV4Pos : kSrcV6Pos;
  // update map for hc_pckt_src
  auto res = bpfAdapter_.bpfUpdateMap(
      bpfAdapter_.getMapFdByName("hc_pckt_srcs_map"), &key, &srcBe);
  if (res) {
    LOG(ERROR) << "cannot insert src address in map: hc_pckt_srcs_map";
    return false;
  }
  VLOG(3) << "Successfully updated hc_pckt_srcs_map with ip: " << src.str();

  // update map for pckt_src
  if (!config_.disableForwarding) {
    res = bpfAdapter_.bpfUpdateMap(
        bpfAdapter_.getMapFdByName("pckt_srcs"), &key, &srcBe);
    if (res) {
      LOG(ERROR) << "cannot insert src address in map: pckt_srcs";
      return false;
    }
    VLOG(3) << "Successfully updated pckt_srcs with ip: " << src.str();
  }

  return true;
}

void KatranLb::enableRecirculation() {
  uint32_t key = kRecirculationIndex;
  int balancer_fd = getKatranProgFd();
  auto res = bpfAdapter_.bpfUpdateMap(
      bpfAdapter_.getMapFdByName("subprograms"), &key, &balancer_fd);
  if (res < 0) {
    throw std::runtime_error("can not update subprograms for recirculation");
  }
}

void KatranLb::featureDiscovering() {
  if (bpfAdapter_.isMapInProg(kBalancerProgName.toString(), "lpm_src_v4")) {
    VLOG(2) << "source based routing is supported";
    features_.srcRouting = true;
  } else {
    features_.srcRouting = false;
  }
  if (bpfAdapter_.isMapInProg(kBalancerProgName.toString(), "decap_dst")) {
    VLOG(2) << "inline decapsulation is supported";
    features_.inlineDecap = true;
  } else {
    features_.inlineDecap = false;
  }
  if (bpfAdapter_.isMapInProg(kBalancerProgName.toString(), "event_pipe")) {
    VLOG(2) << "katran introspection is enabled";
    features_.introspection = true;
  } else {
    features_.introspection = false;
  }
  if (bpfAdapter_.isMapInProg(kBalancerProgName.toString(), "pckt_srcs")) {
    VLOG(2) << "GUE encapsulation is enabled";
    features_.gueEncap = true;
  } else {
    features_.gueEncap = false;
  }
  if (bpfAdapter_.isMapInProg(
          kHealthcheckerProgName.toString(), "hc_pckt_srcs_map")) {
    VLOG(2) << "Direct healthchecking is enabled";
    features_.directHealthchecking = true;
  } else {
    features_.directHealthchecking = false;
  }

  if (bpfAdapter_.isMapInProg(
          kBalancerProgName.toString(), kFlowDebugParentMapName.data())) {
    VLOG(2) << "Flow debug is enabled";
    features_.flowDebug = true;
  } else {
    features_.flowDebug = false;
  }
}

void KatranLb::startIntrospectionRoutines() {
  auto monitor_config = config_.monitorConfig;
  monitor_config.nCpus = katran::BpfAdapter::getPossibleCpus();
  monitor_config.mapFd = bpfAdapter_.getMapFdByName("event_pipe");
  monitor_ = std::make_shared<KatranMonitor>(monitor_config);
}

void KatranLb::loadBpfProgs() {
  int res;
  bool flowDebugInProg = false;

  if (!config_.disableForwarding) {
    flowDebugInProg = bpfAdapter_.isMapInBpfObject(
      config_.balancerProgPath, kFlowDebugParentMapName.data());
    initLrus(flowDebugInProg);
    if (flowDebugInProg) {
      initFlowDebugPrototypeMap();
    }
    res = bpfAdapter_.loadBpfProg(config_.balancerProgPath);
    if (res) {
      throw std::invalid_argument("can't load main bpf program");
    }
  }

  if (config_.enableHc) {
    res = bpfAdapter_.loadBpfProg(config_.healthcheckingProgPath);
    if (res) {
      throw std::invalid_argument(folly::sformat(
          "can't load healthchecking bpf program, error: {}",
          folly::errnoStr(errno)));
    }
  }

  initialSanityChecking(flowDebugInProg);
  featureDiscovering();

  if (!config_.disableForwarding && features_.gueEncap) {
    setupGueEnvironment();
  }

  if (!config_.disableForwarding && features_.inlineDecap) {
    enableRecirculation();
  }

  if (!config_.disableForwarding) {
    // add values to main prog ctl_array
    std::vector<uint32_t> balancer_ctl_keys = {kMacAddrPos};

    for (auto ctl_key : balancer_ctl_keys) {
      res = bpfAdapter_.bpfUpdateMap(
          bpfAdapter_.getMapFdByName("ctl_array"),
          &ctl_key,
          &ctlValues_[ctl_key]);

      if (res != 0) {
        throw std::invalid_argument(folly::sformat(
            "can't update ctl array for main program, error: {}",
            folly::errnoStr(errno)));
      }
    }
  }

  if (config_.enableHc) {
    std::vector<uint32_t> hc_ctl_keys = {kMainIntfPos};
    if (config_.tunnelBasedHCEncap) {
      hc_ctl_keys.push_back(kIpv4TunPos);
      hc_ctl_keys.push_back(kIpv6TunPos);
    }
    for (auto ctl_key : hc_ctl_keys) {
      res = bpfAdapter_.bpfUpdateMap(
          bpfAdapter_.getMapFdByName("hc_ctrl_map"),
          &ctl_key,
          &ctlValues_[ctl_key].ifindex);

      if (res != 0) {
        throw std::invalid_argument(folly::sformat(
            "can't update ctrl map for hc program, error: {}",
            folly::errnoStr(errno)));
      }
    }
    if (features_.directHealthchecking) {
      setupHcEnvironment();
    }
  }
  progsLoaded_ = true;
  if (!config_.disableForwarding && features_.introspection) {
    startIntrospectionRoutines();
    introspectionStarted_ = true;
  }

  if (!config_.disableForwarding) {
    attachLrus(flowDebugInProg);
  }
}

bool KatranLb::reloadBalancerProg(
    const std::string& path,
    folly::Optional<KatranConfig> config) {
  int res;
  if (config_.disableForwarding) {
    return false;
  }

  res = bpfAdapter_.reloadBpfProg(path);
  if (res) {
    return false;
  }

  if (config.has_value()) {
    config_ = *config;
  }

  config_.balancerProgPath = path;

  bool flowDebugInProg = bpfAdapter_.isMapInBpfObject(
      path, kFlowDebugParentMapName.data());
  initialSanityChecking(flowDebugInProg);
  featureDiscovering();

  if (features_.gueEncap) {
    setupGueEnvironment();
  }

  if (features_.inlineDecap) {
    enableRecirculation();
  }

  if (features_.introspection && !introspectionStarted_) {
    startIntrospectionRoutines();
    introspectionStarted_ = true;
  }
  progsReloaded_ = true;
  return true;
}

void KatranLb::attachBpfProgs() {
  if (!progsLoaded_) {
    throw std::invalid_argument("failed to attach bpf prog: prog not loaded");
  }
  int res;
  auto main_fd = bpfAdapter_.getProgFdByName(kBalancerProgName.toString());
  auto interface_index = ctlValues_[kMainIntfPos].ifindex;
  if (standalone_) {
    // attaching main bpf prog in standalone mode
    res = bpfAdapter_.modifyXdpProg(
        main_fd, interface_index, config_.xdpAttachFlags);
    if (res != 0) {
      throw std::invalid_argument(folly::sformat(
          "can't attach main bpf prog "
          "to main inteface, error: {}",
          folly::errnoStr(errno)));
    }
  } else if (!config_.disableForwarding) {
    // we are in "shared" mode and must register ourself in root xdp prog
    rootMapFd_ = bpfAdapter_.getPinnedBpfObject(config_.rootMapPath);
    if (rootMapFd_ < 0) {
      throw std::invalid_argument(folly::sformat(
          "can't get fd of xdp's root map, error: {}", folly::errnoStr(errno)));
    }
    res = bpfAdapter_.bpfUpdateMap(rootMapFd_, &config_.rootMapPos, &main_fd);
    if (res) {
      throw std::invalid_argument(folly::sformat(
          "can't register in root array, error: {}", folly::errnoStr(errno)));
    }
  }

  if (config_.enableHc && !progsReloaded_) {
    // attaching healthchecking bpf prog.
    auto hc_fd = getHealthcheckerProgFd();
    res = bpfAdapter_.addTcBpfFilter(
        hc_fd,
        ctlValues_[kHcIntfPos].ifindex,
        "katran-healthchecker",
        config_.priority,
        TC_EGRESS);
    if (res != 0) {
      if (standalone_) {
        // will try to remove main bpf prog.
        bpfAdapter_.detachXdpProg(interface_index, config_.xdpAttachFlags);
      } else {
        bpfAdapter_.bpfMapDeleteElement(rootMapFd_, &config_.rootMapPos);
      }
      throw std::invalid_argument(folly::sformat(
          "can't attach healthchecking bpf prog "
          "to given inteface: {}, error: {}",
          config_.hcInterface,
          folly::errnoStr(errno)));
    }
  }
  progsAttached_ = true;
}

bool KatranLb::changeMac(const std::vector<uint8_t> newMac) {
  uint32_t key = kMacAddrPos;

  VLOG(4) << "adding new mac address";

  if (newMac.size() != kMacBytes) {
    return false;
  }
  for (int i = 0; i < kMacBytes; i++) {
    ctlValues_[kMacAddrPos].mac[i] = newMac[i];
  }
  if (!config_.testing) {
    if (!config_.disableForwarding) {
      auto res = bpfAdapter_.bpfUpdateMap(
          bpfAdapter_.getMapFdByName("ctl_array"),
          &key,
          &ctlValues_[kMacAddrPos].mac);
      if (res != 0) {
        lbStats_.bpfFailedCalls++;
        VLOG(4) << "can't add new mac address";
        return false;
      }
    }

    if (features_.directHealthchecking) {
      key = kHcDstMacPos;
      auto res = bpfAdapter_.bpfUpdateMap(
          bpfAdapter_.getMapFdByName("hc_pckt_macs"),
          &key,
          &ctlValues_[kMacAddrPos].mac);
      if (res != 0) {
        lbStats_.bpfFailedCalls++;
        VLOG(4) << "can't add new mac address for direct healthchecks";
        return false;
      }
    }
  }
  return true;
}

std::vector<uint8_t> KatranLb::getMac() {
  return std::vector<uint8_t>(
      std::begin(ctlValues_[kMacAddrPos].mac),
      std::end(ctlValues_[kMacAddrPos].mac));
}

std::map<int, uint32_t> KatranLb::getIndexOfNetworkInterfaces() {
  std::map<int, uint32_t> res;
  res[kMainIntfPos] = ctlValues_[kMainIntfPos].ifindex;
  if (config_.enableHc) {
    res[kHcIntfPos] = ctlValues_[kHcIntfPos].ifindex;
    if (config_.tunnelBasedHCEncap) {
      res[kIpv4TunPos] = ctlValues_[kIpv4TunPos].ifindex;
      res[kIpv6TunPos] = ctlValues_[kIpv6TunPos].ifindex;
    }
  }
  return res;
}

bool KatranLb::addVip(const VipKey& vip, const uint32_t flags) {
  if (config_.disableForwarding) {
    LOG(ERROR) << "Ignoring addVip call on non-forwarding instance";
    return false;
  }

  if (validateAddress(vip.address) == AddressType::INVALID) {
    LOG(ERROR) << "Invalid Vip address: " << vip.address;
    return false;
  }
  LOG(INFO) << folly::format(
      "adding new vip: {}:{}:{}", vip.address, vip.port, vip.proto);

  if (vipNums_.size() == 0) {
    LOG(INFO) << "exhausted vip's space";
    return false;
  }
  if (vips_.find(vip) != vips_.end()) {
    LOG(INFO) << "trying to add already existing vip";
    return false;
  }
  auto vip_num = vipNums_[0];
  vipNums_.pop_front();
  vips_.emplace(
      vip, Vip(vip_num, flags, config_.chRingSize, config_.hashFunction));
  if (!config_.testing) {
    vip_meta meta;
    meta.vip_num = vip_num;
    meta.flags = flags;
    updateVipMap(ModifyAction::ADD, vip, &meta);
  }
  return true;
}

bool KatranLb::changeHashFunctionForVip(const VipKey& vip, HashFunction func) {
  if (config_.disableForwarding) {
    LOG(ERROR) << "Ignoring addVip call on non-forwarding instance";
    return false;
  }

  if (validateAddress(vip.address) == AddressType::INVALID) {
    LOG(ERROR) << "Invalid Vip address: " << vip.address;
    return false;
  }
  auto vip_iter = vips_.find(vip);
  if (vip_iter == vips_.end()) {
    LOG(INFO) << "trying to change non existing vip";
    return false;
  }
  vip_iter->second.setHashFunction(func);
  auto positions = vip_iter->second.recalculateHashRing();
  programHashRing(positions, vip_iter->second.getVipNum());
  return true;
}

bool KatranLb::delVip(const VipKey& vip) {
  if (config_.disableForwarding) {
    LOG(ERROR) << "Ignoring delVip call on non-forwarding instance";
    return false;
  }

  LOG(INFO) << folly::format(
      "deleting vip: {}:{}:{}", vip.address, vip.port, vip.proto);

  auto vip_iter = vips_.find(vip);
  if (vip_iter == vips_.end()) {
    LOG(INFO) << "trying to delete non-existing vip";
    return false;
  }

  auto vip_reals = vip_iter->second.getReals();
  // decreasing ref count for reals. delete em if it became 0
  for (auto& vip_real : vip_reals) {
    auto real_name = numToReals_[vip_real];
    decreaseRefCountForReal(real_name);
  }
  vipNums_.push_back(vip_iter->second.getVipNum());
  if (!config_.testing) {
    updateVipMap(ModifyAction::DEL, vip);
  }
  vips_.erase(vip_iter);
  return true;
}

std::vector<VipKey> KatranLb::getAllVips() {
  if (config_.disableForwarding) {
    LOG(ERROR) << "getAllVips called on non-forwarding instance";
    return std::vector<VipKey>();
  }

  std::vector<VipKey> vips(vips_.size());
  int i = 0;
  for (auto& vip : vips_) {
    vips[i++] = vip.first;
  }
  return vips;
}

uint32_t KatranLb::getVipFlags(const VipKey& vip) {
  if (config_.disableForwarding) {
    LOG(ERROR) << "getVipFlags called on non-forwarding instance";
    throw std::invalid_argument(
        "getVipFlags called on non-forwarding instance");
  }

  auto vip_iter = vips_.find(vip);
  if (vip_iter == vips_.end()) {
    throw std::invalid_argument(folly::sformat(
        "trying to get flags from non-existing vip: {}", vip.address));
  }
  return vip_iter->second.getVipFlags();
}

bool KatranLb::modifyVip(const VipKey& vip, uint32_t flag, bool set) {
  LOG(INFO) << folly::format(
      "modifying vip: {}:{}:{}", vip.address, vip.port, vip.proto);

  auto vip_iter = vips_.find(vip);
  if (vip_iter == vips_.end()) {
    LOG(INFO) << folly::sformat(
        "trying to modify non-existing vip: {}", vip.address);
    return false;
  }
  if (set) {
    vip_iter->second.setVipFlags(flag);
  } else {
    vip_iter->second.unsetVipFlags(flag);
  }
  if (!config_.testing) {
    vip_meta meta;
    meta.vip_num = vip_iter->second.getVipNum();
    meta.flags = vip_iter->second.getVipFlags();
    return updateVipMap(ModifyAction::ADD, vip, &meta);
  }
  return true;
}

bool KatranLb::addRealForVip(const NewReal& real, const VipKey& vip) {
  if (config_.disableForwarding) {
    LOG(ERROR) << "addRealForVip called on non-forwarding instance";
    return false;
  }
  std::vector<NewReal> reals;
  reals.push_back(real);
  return modifyRealsForVip(ModifyAction::ADD, reals, vip);
}

bool KatranLb::delRealForVip(const NewReal& real, const VipKey& vip) {
  if (config_.disableForwarding) {
    LOG(ERROR) << "delRealForVip called on non-forwarding instance";
    return false;
  }
  std::vector<NewReal> reals;
  reals.push_back(real);
  return modifyRealsForVip(ModifyAction::DEL, reals, vip);
}

bool KatranLb::modifyReal(const std::string& real, uint8_t flags, bool set) {
  if (config_.disableForwarding) {
    LOG(ERROR) << "modifyReal called on non-forwarding instance";
    return false;
  }
  if (validateAddress(real) == AddressType::INVALID) {
    LOG(ERROR) << "invalid real's address: " << real;
    return false;
  }

  VLOG(4) << folly::format("modifying real: {} ", real);
  folly::IPAddress raddr(real);
  auto real_iter = reals_.find(raddr);
  if (real_iter == reals_.end()) {
    LOG(INFO) << folly::sformat("trying to modify non-existing real: {}", real);
    return false;
  }
  flags &= ~V6DADDR; // to keep IPv4/IPv6 specific flag
  if (set) {
    real_iter->second.flags |= flags;
  } else {
    real_iter->second.flags &= ~flags;
  }
  reals_[raddr].flags = real_iter->second.flags;
  if (!config_.testing) {
    updateRealsMap(raddr, real_iter->second.num, real_iter->second.flags);
  }
  return true;
}

bool KatranLb::modifyRealsForVip(
    const ModifyAction action,
    const std::vector<NewReal>& reals,
    const VipKey& vip) {
  if (config_.disableForwarding) {
    LOG(ERROR) << "delRealForVip called on non-forwarding instance";
    return false;
  }

  UpdateReal ureal;
  std::vector<UpdateReal> ureals;
  ureal.action = action;

  auto vip_iter = vips_.find(vip);
  if (vip_iter == vips_.end()) {
    LOG(INFO) << folly::sformat(
        "trying to modify reals for non existing vip: {}", vip.address);
    return false;
  }
  auto cur_reals = vip_iter->second.getReals();
  for (const auto& real : reals) {
    if (validateAddress(real.address) == AddressType::INVALID) {
      LOG(ERROR) << "Invalid real's address: " << real.address;
      continue;
    }
    folly::IPAddress raddr(real.address);
    VLOG(4) << folly::format(
        "modifying real: {} with weight {} for vip {}:{}:{}",
        real.address,
        real.weight,
        vip.address,
        vip.port,
        vip.proto);

    if (action == ModifyAction::DEL) {
      auto real_iter = reals_.find(raddr);
      if (real_iter == reals_.end()) {
        LOG(INFO) << "trying to delete non-existing real";
        continue;
      }
      if (std::find(
              cur_reals.begin(), cur_reals.end(), real_iter->second.num) ==
          cur_reals.end()) {
        // this real doesn't belong to this vip
        LOG(INFO) << folly::sformat(
            "trying to delete non-existing real for the VIP: {}", vip.address);
        continue;
      }
      ureal.updatedReal.num = real_iter->second.num;
      decreaseRefCountForReal(raddr);
    } else {
      auto real_iter = reals_.find(raddr);
      if (real_iter != reals_.end()) {
        if (std::find(
                cur_reals.begin(), cur_reals.end(), real_iter->second.num) ==
            cur_reals.end()) {
          // increment ref count if it's a new real for this vip
          increaseRefCountForReal(raddr, real.flags);
          cur_reals.push_back(real_iter->second.num);
        }
        ureal.updatedReal.num = real_iter->second.num;
      } else {
        auto rnum = increaseRefCountForReal(raddr, real.flags);
        if (rnum == config_.maxReals) {
          LOG(INFO) << "exhausted real's space";
          continue;
        }
        ureal.updatedReal.num = rnum;
      }
      ureal.updatedReal.weight = real.weight;
      ureal.updatedReal.hash = raddr.hash();
    }
    ureals.push_back(ureal);
  }

  auto ch_positions = vip_iter->second.batchRealsUpdate(ureals);
  auto vip_num = vip_iter->second.getVipNum();
  programHashRing(ch_positions, vip_num);
  return true;
}

void KatranLb::programHashRing(
    const std::vector<RealPos>& chPositions,
    const uint32_t vipNum) {
  if (!config_.testing) {
    auto ch_fd = bpfAdapter_.getMapFdByName("ch_rings");
    uint32_t key;
    int res;
    for (auto pos : chPositions) {
      key = vipNum * config_.chRingSize + pos.pos;
      res = bpfAdapter_.bpfUpdateMap(ch_fd, &key, &pos.real);
      if (res != 0) {
        lbStats_.bpfFailedCalls++;
        LOG(INFO) << "can't update ch ring"
                  << ", error: " << folly::errnoStr(errno);
      }
    }
  }
}

std::vector<NewReal> KatranLb::getRealsForVip(const VipKey& vip) {
  if (config_.disableForwarding) {
    LOG(ERROR) << "getRealsForVip called on non-forwarding instance";
    return std::vector<NewReal>();
  }

  auto vip_iter = vips_.find(vip);
  if (vip_iter == vips_.end()) {
    throw std::invalid_argument(folly::sformat(
        "trying to get real from non-existing vip: {}", vip.address));
  }
  auto vip_reals_ids = vip_iter->second.getRealsAndWeight();
  std::vector<NewReal> reals(vip_reals_ids.size());
  int i = 0;
  for (auto real_id : vip_reals_ids) {
    reals[i].weight = real_id.weight;
    reals[i].address = numToReals_[real_id.num].str();
    reals[i].flags = reals_[numToReals_[real_id.num]].flags;
    ++i;
  }
  return reals;
}

int64_t KatranLb::getIndexForReal(const std::string& real) {
  if (config_.disableForwarding) {
    LOG(ERROR) << "getIndexForReal called on non-forwarding instance";
    return -1;
  }

  if (validateAddress(real) != AddressType::INVALID) {
    folly::IPAddress raddr(real);
    auto real_iter = reals_.find(raddr);
    if (real_iter != reals_.end()) {
      return real_iter->second.num;
    }
  }
  return kError;
}

int KatranLb::addSrcRoutingRule(
    const std::vector<std::string>& srcs,
    const std::string& dst) {
  int num_errors = 0;
  if (config_.disableForwarding) {
    LOG(ERROR) << "addSrcRoutingRule called on non-forwarding instance";
    return kError;
  }
  if (!features_.srcRouting && !config_.testing) {
    LOG(ERROR) << "Source based routing is not enabled in forwarding plane";
    return kError;
  }
  if (validateAddress(dst) == AddressType::INVALID) {
    LOG(ERROR) << "Invalid dst address for src routing: " << dst;
    return kError;
  }
  std::vector<folly::CIDRNetwork> src_networks;
  for (auto& src : srcs) {
    if (validateAddress(src, true) != AddressType::NETWORK) {
      LOG(ERROR) << "trying to add incorrect addr for src routing " << src;
      num_errors++;
      // dont want to stop even if one addr is incorrect.
      continue;
    }
    if (lpmSrcMapping_.size() + src_networks.size() + 1 >
        config_.maxLpmSrcSize) {
      LOG(ERROR) << "source mappings map size is exhausted";
      // num errors is equal to number of routes which don't have space to be
      // installed to
      num_errors += (srcs.size() - src_networks.size());
      // no point to continue. bailing out
      break;
    }
    // we already validated above that this is network address so wont throw
    src_networks.push_back(folly::IPAddress::createNetwork(src));
  }
  auto rval = addSrcRoutingRule(src_networks, dst);
  if (rval == kError) {
    num_errors = rval;
  }
  return num_errors;
}

int KatranLb::addSrcRoutingRule(
    const std::vector<folly::CIDRNetwork>& srcs,
    const std::string& dst) {
  if (config_.disableForwarding) {
    LOG(ERROR) << "addSrcRoutingRule called on non-forwarding instance";
    return kError;
  }
  if (!features_.srcRouting && !config_.testing) {
    LOG(ERROR) << "Source based routing is not enabled in forwarding plane";
    return kError;
  }
  if (validateAddress(dst) == AddressType::INVALID) {
    LOG(ERROR) << "Invalid dst address for src routing: " << dst;
    return kError;
  }
  for (auto& src : srcs) {
    if (lpmSrcMapping_.size() + 1 > config_.maxLpmSrcSize) {
      LOG(ERROR) << "source mappings map size is exhausted";
      // no point to continue. bailing out
      return kError;
    }
    auto rnum = increaseRefCountForReal(folly::IPAddress(dst));
    if (rnum == config_.maxReals) {
      LOG(ERROR) << "exhausted real's space";
      // all src using same dst. no point to continue if we can't add this dst
      return kError;
    }
    lpmSrcMapping_[src] = rnum;
    if (!config_.testing) {
      modifyLpmSrcRule(ModifyAction::ADD, src, rnum);
    }
  }
  return 0;
}

bool KatranLb::delSrcRoutingRule(const std::vector<std::string>& srcs) {
  if (config_.disableForwarding) {
    LOG(ERROR) << "delSrcRoutingRule called on non-forwarding instance";
    return false;
  }
  if (!features_.srcRouting && !config_.testing) {
    LOG(ERROR) << "Source based routing is not enabled in forwarding plane";
    return false;
  }
  std::vector<folly::CIDRNetwork> src_networks;
  for (auto& src : srcs) {
    auto network = folly::IPAddress::tryCreateNetwork(src);
    if (network.hasValue()) {
      src_networks.push_back(network.value());
    }
  }
  return delSrcRoutingRule(src_networks);
}

bool KatranLb::delSrcRoutingRule(const std::vector<folly::CIDRNetwork>& srcs) {
  if (config_.disableForwarding) {
    LOG(ERROR) << "delSrcRoutingRule called on non-forwarding instance";
    return false;
  }
  if (!features_.srcRouting && !config_.testing) {
    LOG(ERROR) << "Source based routing is not enabled in forwarding plane";
    return false;
  }
  for (auto& src : srcs) {
    auto src_iter = lpmSrcMapping_.find(src);
    if (src_iter == lpmSrcMapping_.end()) {
      LOG(ERROR) << "trying to delete non existing src mapping " << src.first
                 << "/" << src.second;
      continue;
    }
    auto dst = numToReals_[src_iter->second];
    decreaseRefCountForReal(dst);
    if (!config_.testing) {
      modifyLpmSrcRule(ModifyAction::DEL, src, src_iter->second);
    }
    lpmSrcMapping_.erase(src_iter);
  }
  return true;
}

bool KatranLb::clearAllSrcRoutingRules() {
  if (config_.disableForwarding) {
    LOG(ERROR) << "clearAllSrcRoutingRules called on non-forwarding instance";
    return false;
  }
  if (!features_.srcRouting && !config_.testing) {
    LOG(ERROR) << "Source based routing is not enabled in forwarding plane";
    return false;
  }
  for (auto& rule : lpmSrcMapping_) {
    auto dst_iter = numToReals_.find(rule.second);
    decreaseRefCountForReal(dst_iter->second);
    if (!config_.testing) {
      modifyLpmSrcRule(ModifyAction::DEL, rule.first, rule.second);
    }
  }
  lpmSrcMapping_.clear();
  return true;
}

uint32_t KatranLb::getSrcRoutingRuleSize() {
  return lpmSrcMapping_.size();
}

std::unordered_map<std::string, std::string> KatranLb::getSrcRoutingRule() {
  std::unordered_map<std::string, std::string> src_mapping;
  if (config_.disableForwarding) {
    LOG(ERROR) << "getSrcRoutingRule called on non-forwarding instance";
    return src_mapping;
  }
  if (!features_.srcRouting && !config_.testing) {
    LOG(ERROR) << "Source based routing is not enabled in forwarding plane";
    return src_mapping;
  }
  for (auto& src : lpmSrcMapping_) {
    auto real = numToReals_[src.second];
    auto src_network =
        folly::sformat("{}/{}", src.first.first.str(), src.first.second);
    src_mapping[src_network] = real.str();
  }
  return src_mapping;
}

std::unordered_map<folly::CIDRNetwork, std::string>
KatranLb::getSrcRoutingRuleCidr() {
  std::unordered_map<folly::CIDRNetwork, std::string> src_mapping;
  if (config_.disableForwarding) {
    LOG(ERROR) << "getSrcRoutingRuleCidr called on non-forwarding instance";
    return src_mapping;
  }
  if (!features_.srcRouting && !config_.testing) {
    LOG(ERROR) << "Source based routing is not enabled in forwarding plane";
    return src_mapping;
  }
  for (auto& src : lpmSrcMapping_) {
    auto real = numToReals_[src.second];
    src_mapping[src.first] = real.str();
  }
  return src_mapping;
}

const std::unordered_map<uint32_t, std::string> KatranLb::getNumToRealMap() {
  std::unordered_map<uint32_t, std::string> reals;
  for (const auto& real : numToReals_) {
    reals[real.first] = real.second.str();
  }
  return reals;
}

bool KatranLb::changeKatranMonitorForwardingState(KatranMonitorState state) {
  uint32_t key = kIntrospectionGkPos;
  struct ctl_value value;
  switch (state) {
    case KatranMonitorState::ENABLED:
      value.value = 1;
      break;
    case KatranMonitorState::DISABLED:
      value.value = 0;
      break;
  }
  auto res = bpfAdapter_.bpfUpdateMap(
      bpfAdapter_.getMapFdByName("ctl_array"), &key, &value);
  if (res != 0) {
    LOG(INFO) << "can't change state of introspection forwarding plane";
    lbStats_.bpfFailedCalls++;
    return false;
  }
  return true;
}

bool KatranLb::stopKatranMonitor() {
  if (config_.disableForwarding) {
    LOG(ERROR) << "stopKatranMonitor called on non-forwarding instance";
    return false;
  }

  if (!monitor_) {
    return false;
  }
  if (!changeKatranMonitorForwardingState(KatranMonitorState::DISABLED)) {
    return false;
  }
  monitor_->stopMonitor();
  return true;
}

std::unique_ptr<folly::IOBuf> KatranLb::getKatranMonitorEventBuffer(
    EventId event) {
  if (config_.disableForwarding || !monitor_) {
    return nullptr;
  }
  return monitor_->getEventBuffer(event);
}

bool KatranLb::restartKatranMonitor(
    uint32_t limit,
    folly::Optional<PcapStorageFormat> storage) {
  if (config_.disableForwarding || !monitor_) {
    return false;
  }
  if (!changeKatranMonitorForwardingState(KatranMonitorState::ENABLED)) {
    return false;
  }
  monitor_->restartMonitor(limit, storage);
  return true;
}

KatranMonitorStats KatranLb::getKatranMonitorStats() {
  struct KatranMonitorStats stats;
  if (config_.disableForwarding || !monitor_) {
    return stats;
  }
  auto writer_stats = monitor_->getWriterStats();
  stats.limit = writer_stats.limit;
  stats.amount = writer_stats.amount;
  stats.bufferFull = writer_stats.bufferFull;
  return stats;
}

bool KatranLb::modifyLpmSrcRule(
    ModifyAction action,
    const folly::CIDRNetwork& src,
    uint32_t rnum) {
  return modifyLpmMap("lpm_src", action, src, &rnum);
}

bool KatranLb::modifyLpmMap(
    const std::string& lpmMapNamePrefix,
    ModifyAction action,
    const folly::CIDRNetwork& prefix,
    void* value) {
  auto lpm_addr = IpHelpers::parseAddrToBe(prefix.first.str());
  if (prefix.first.isV4()) {
    struct v4_lpm_key key_v4 = {
        .prefixlen = prefix.second, .addr = lpm_addr.daddr};
    std::string mapName = lpmMapNamePrefix + "_v4";
    if (action == ModifyAction::ADD) {
      auto res = bpfAdapter_.bpfUpdateMap(
          bpfAdapter_.getMapFdByName(mapName), &key_v4, value);
      if (res != 0) {
        LOG(INFO) << "can't add new element into " << mapName
                  << ", error: " << folly::errnoStr(errno);
        lbStats_.bpfFailedCalls++;
        return false;
      }
    } else {
      auto res = bpfAdapter_.bpfMapDeleteElement(
          bpfAdapter_.getMapFdByName(mapName), &key_v4);
      if (res != 0) {
        LOG(INFO) << "can't delete element from " << mapName
                  << ", error: " << folly::errnoStr(errno);
        lbStats_.bpfFailedCalls++;
        return false;
      }
    }
  } else {
    struct v6_lpm_key key_v6 = {
        .prefixlen = prefix.second,
    };
    std::string mapName = lpmMapNamePrefix + "_v6";
    std::memcpy(key_v6.addr, lpm_addr.v6daddr, 16);
    if (action == ModifyAction::ADD) {
      auto res = bpfAdapter_.bpfUpdateMap(
          bpfAdapter_.getMapFdByName(mapName), &key_v6, value);
      if (res != 0) {
        LOG(INFO) << "can't add new element into " << mapName
                  << ", error: " << folly::errnoStr(errno);
        lbStats_.bpfFailedCalls++;
        return false;
      }
    } else {
      auto res = bpfAdapter_.bpfMapDeleteElement(
          bpfAdapter_.getMapFdByName(mapName), &key_v6);
      if (res != 0) {
        LOG(INFO) << "can't delete element from " << mapName
                  << ", error: " << folly::errnoStr(errno);
        lbStats_.bpfFailedCalls++;
        return false;
      }
    }
  }
  return true;
}

bool KatranLb::addInlineDecapDst(const std::string& dst) {
  if (config_.disableForwarding) {
    LOG(ERROR) << "addInlineDecapDst called on non-forwarding instance";
    return false;
  }
  if (!features_.inlineDecap && !config_.testing) {
    LOG(ERROR) << "source based routing is not enabled in forwarding plane";
    return false;
  }
  if (validateAddress(dst) == AddressType::INVALID) {
    LOG(ERROR) << "invalid decap destination address: " << dst;
    return false;
  }
  folly::IPAddress daddr(dst);
  if (decapDsts_.find(daddr) != decapDsts_.end()) {
    LOG(ERROR) << "trying to add already existing decap dst";
    return false;
  }
  if (decapDsts_.size() + 1 > config_.maxDecapDst) {
    LOG(ERROR) << "size of decap destinations map is exhausted";
    return false;
  }
  VLOG(2) << "adding decap dst " << dst;
  decapDsts_.insert(daddr);
  if (!config_.testing) {
    modifyDecapDst(ModifyAction::ADD, daddr);
  }
  return true;
}

bool KatranLb::delInlineDecapDst(const std::string& dst) {
  if (config_.disableForwarding) {
    LOG(ERROR) << "delInlineDecapDst called on non-forwarding instance";
    return false;
  }
  if (!features_.inlineDecap && !config_.testing) {
    LOG(ERROR) << "source based routing is not enabled in forwarding plane";
    return false;
  }
  if (validateAddress(dst) == AddressType::INVALID) {
    LOG(ERROR) << "provided address in invalid format: " << dst;
    return false;
  }
  folly::IPAddress daddr(dst);
  auto dst_iter = decapDsts_.find(daddr);
  if (dst_iter == decapDsts_.end()) {
    LOG(ERROR) << "trying to delete non-existing decap dst " << dst;
    return false;
  }
  VLOG(2) << "deleting decap dst " << dst;
  decapDsts_.erase(dst_iter);
  if (!config_.testing) {
    modifyDecapDst(ModifyAction::DEL, daddr);
  }
  return true;
}

std::vector<std::string> KatranLb::getInlineDecapDst() {
  if (config_.disableForwarding) {
    LOG(ERROR) << "getInlineDecapDst called on non-forwarding instance";
    return std::vector<std::string>();
  }
  std::vector<std::string> dsts;
  for (auto& dst : decapDsts_) {
    dsts.push_back(dst.str());
  }
  return dsts;
}

bool KatranLb::modifyDecapDst(
    ModifyAction action,
    const folly::IPAddress& dst,
    uint32_t flags) {
  auto addr = IpHelpers::parseAddrToBe(dst);
  if (action == ModifyAction::ADD) {
    auto res = bpfAdapter_.bpfUpdateMap(
        bpfAdapter_.getMapFdByName("decap_dst"), &addr, &flags);
    if (res != 0) {
      LOG(ERROR) << "error while adding dst for inline decap " << dst
                 << ", error: " << folly::errnoStr(errno);
      lbStats_.bpfFailedCalls++;
      return false;
    }
  } else {
    auto res = bpfAdapter_.bpfMapDeleteElement(
        bpfAdapter_.getMapFdByName("decap_dst"), &addr);
    if (res != 0) {
      LOG(ERROR) << "error while deleting dst for inline decap " << dst
                 << ", error: " << folly::errnoStr(errno);
      lbStats_.bpfFailedCalls++;
      return false;
    }
  }
  return true;
}

void KatranLb::modifyQuicRealsMapping(
    const ModifyAction action,
    const std::vector<QuicReal>& reals) {
  if (config_.disableForwarding) {
    LOG(ERROR) << "modifyQuicRealsMapping ignored for non-forwarding instance";
    return;
  }
  std::unordered_map<uint32_t, uint32_t> to_update;
  for (auto& real : reals) {
    if (validateAddress(real.address) == AddressType::INVALID) {
      LOG(ERROR) << "Invalid quic real's address: " << real.address;
      continue;
    }
    if (real.id > kMaxQuicId) {
      LOG(ERROR) << "trying to add mapping for id out of assigned space";
      continue;
    }
    VLOG(4) << folly::sformat(
        "modifying quic's real {} id {:x}", real.address, real.id);
    auto raddr = folly::IPAddress(real.address);
    auto real_iter = quicMapping_.find(real.id);
    if (action == ModifyAction::DEL) {
      if (real_iter == quicMapping_.end()) {
        LOG(ERROR) << folly::sformat(
            "trying to delete nonexisting mapping for id {:x} address {}",
            real.id,
            real.address);
        continue;
      }
      if (real_iter->second != raddr) {
        LOG(ERROR) << folly::sformat(
            "deleted id {} pointed to diffrent address {} than given {}",
            real.id,
            real_iter->second.str(),
            real.address);
        continue;
      }
      decreaseRefCountForReal(raddr);
      quicMapping_.erase(real_iter);
    } else {
      if (real_iter != quicMapping_.end()) {
        if (real_iter->second == raddr) {
          continue;
        }
        LOG(WARNING) << folly::sformat(
            "overriding address {} for existing mapping id {} address {}",
            real_iter->second.str(),
            real.id,
            real.address);
        decreaseRefCountForReal(real_iter->second);
      }
      auto rnum = increaseRefCountForReal(raddr);
      if (rnum == config_.maxReals) {
        LOG(ERROR) << "exhausted real's space";
        continue;
      }
      to_update[real.id] = rnum;
      quicMapping_[real.id] = raddr;
    }
  }
  if (!config_.testing) {
    auto server_id_map_fd = bpfAdapter_.getMapFdByName("server_id_map");
    uint32_t id, rnum;
    int res;
    for (auto& mapping : to_update) {
      id = mapping.first;
      rnum = mapping.second;
      res = bpfAdapter_.bpfUpdateMap(server_id_map_fd, &id, &rnum);
      if (res != 0) {
        LOG(ERROR) << "can't update quic mapping, error: "
                   << folly::errnoStr(errno);
        lbStats_.bpfFailedCalls++;
      }
    }
  }
}

std::vector<QuicReal> KatranLb::getQuicRealsMapping() {
  std::vector<QuicReal> reals;
  if (config_.disableForwarding) {
    LOG(ERROR) << "getQuicRealsMapping called on non-forwarding instance";
    return reals;
  }
  QuicReal real;
  for (auto& mapping : quicMapping_) {
    real.id = mapping.first;
    real.address = mapping.second.str();
    reals.push_back(real);
  }
  return reals;
}

lb_stats KatranLb::getStatsForVip(const VipKey& vip) {
  auto vip_iter = vips_.find(vip);
  if (vip_iter == vips_.end()) {
    LOG(INFO) << "trying to get stats for non-existing vip";
    return lb_stats{};
  }
  auto num = vip_iter->second.getVipNum();
  return getLbStats(num);
}

lb_stats KatranLb::getLruStats() {
  return getLbStats(config_.maxVips + kLruCntrOffset);
}

lb_stats KatranLb::getLruMissStats() {
  return getLbStats(config_.maxVips + kLruMissOffset);
}

lb_stats KatranLb::getLruFallbackStats() {
  return getLbStats(config_.maxVips + kLruFallbackOffset);
}

lb_stats KatranLb::getIcmpTooBigStats() {
  return getLbStats(config_.maxVips + kIcmpTooBigOffset);
}

lb_stats KatranLb::getQuicRoutingStats() {
  return getLbStats(config_.maxVips + kQuicRoutingOffset);
}

lb_stats KatranLb::getQuicCidVersionStats() {
  return getLbStats(config_.maxVips + kQuicCidVersionOffset);
}

lb_stats KatranLb::getQuicCidDropStats() {
  return getLbStats(config_.maxVips + kQuicCidDropOffset);
}

lb_stats KatranLb::getTcpServerIdRoutingStats() {
  return getLbStats(config_.maxVips + kTcpServerIdRoutingOffset);
}

lb_stats KatranLb::getSrcRoutingStats() {
  return getLbStats(config_.maxVips + kLpmSrcOffset);
}

lb_stats KatranLb::getInlineDecapStats() {
  return getLbStats(config_.maxVips + kInlineDecapOffset);
}

lb_stats KatranLb::getRealStats(uint32_t index) {
  return getLbStats(index, "reals_stats");
}

lb_stats KatranLb::getLbStats(uint32_t position, const std::string& map) {
  if (config_.disableForwarding) {
    LOG(ERROR) << "getLbStats called on non-forwarding instance";
    return lb_stats{};
  }
  unsigned int nr_cpus = BpfAdapter::getPossibleCpus();
  if (nr_cpus < 0) {
    LOG(ERROR) << "Error while getting number of possible cpus";
    return lb_stats();
  }
  lb_stats stats[nr_cpus];
  lb_stats sum_stat = {};

  if (!config_.testing) {
    auto res = bpfAdapter_.bpfMapLookupElement(
        bpfAdapter_.getMapFdByName(map), &position, stats);
    if (!res) {
      for (auto& stat : stats) {
        sum_stat.v1 += stat.v1;
        sum_stat.v2 += stat.v2;
      }
    } else {
      lbStats_.bpfFailedCalls++;
    }
  }
  return sum_stat;
}

HealthCheckProgStats KatranLb::getStatsForHealthCheckProgram() {
  unsigned int nr_cpus = BpfAdapter::getPossibleCpus();
  if (nr_cpus < 0) {
    LOG(ERROR) << "Error while getting number of possible cpus";
    return HealthCheckProgStats();
  }
  uint32_t stats_index = kDefaultStatsIndex;
  HealthCheckProgStats stats[nr_cpus];
  HealthCheckProgStats total_stats = {};
  if (!config_.testing) {
    auto res = bpfAdapter_.bpfMapLookupElement(
        bpfAdapter_.getMapFdByName("hc_stats_map"), &stats_index, stats);
    if (res) {
      lbStats_.bpfFailedCalls++;
    } else {
      for (auto& perCpuStat : stats) {
        total_stats.packetsProcessed += perCpuStat.packetsProcessed;
        total_stats.packetsSkipped += perCpuStat.packetsSkipped;
        total_stats.packetsDropped += perCpuStat.packetsDropped;
        total_stats.packetsTooBig += perCpuStat.packetsTooBig;
      }
    }
  }
  return total_stats;
}

KatranBpfMapStats KatranLb::getBpfMapStats(const std::string& map) {
  KatranBpfMapStats map_stats = {0};
  int res = bpfAdapter_.getBpfMapMaxSize(map);
  if (res < 0) {
    throw std::runtime_error(folly::sformat(
        "Failed to gather max entry count for map '{}'. res: {}", map, res));
  } else {
    map_stats.maxEntries = res;
  }
  res = bpfAdapter_.getBpfMapUsedSize(map);
  if (res < 0) {
    throw std::runtime_error(folly::sformat(
        "Failed to gather current entry count for map '{}'. res: {}",
        map,
        res));
  } else {
    map_stats.currentEntries = res;
  }
  return map_stats;
}

bool KatranLb::addHealthcheckerDst(
    const uint32_t somark,
    const std::string& dst) {
  if (!config_.enableHc) {
    return false;
  }
  if (validateAddress(dst) == AddressType::INVALID) {
    LOG(ERROR) << "Invalid healthcheck's destanation: " << dst;
    return false;
  }
  VLOG(4) << folly::format(
      "adding healtcheck with so_mark {} to dst {}", somark, dst);
  folly::IPAddress hcaddr(dst);
  uint32_t key = somark;
  beaddr addr;

  auto hc_iter = hcReals_.find(somark);
  if (hc_iter == hcReals_.end() && hcReals_.size() == config_.maxReals) {
    LOG(INFO) << "healthchecker's reals space exhausted";
    return false;
  }
  // for md bassed tunnels remote_ipv4 must be in host endian format
  if (hcaddr.isV4() && !features_.directHealthchecking) {
    addr = IpHelpers::parseAddrToInt(hcaddr);
  } else {
    addr = IpHelpers::parseAddrToBe(hcaddr);
  }
  if (!config_.testing) {
    auto res = bpfAdapter_.bpfUpdateMap(
        bpfAdapter_.getMapFdByName("hc_reals_map"), &key, &addr);
    if (res != 0) {
      LOG(INFO) << "can't add new real for healthchecking, error: "
                << folly::errnoStr(errno);
      lbStats_.bpfFailedCalls++;
      return false;
    }
  }
  hcReals_[somark] = hcaddr;
  return true;
}

bool KatranLb::delHealthcheckerDst(const uint32_t somark) {
  if (!config_.enableHc) {
    return false;
  }
  VLOG(4) << folly::format("deleting healtcheck with so_mark {}", somark);

  uint32_t key = somark;

  auto hc_iter = hcReals_.find(somark);
  if (hc_iter == hcReals_.end()) {
    LOG(INFO) << "trying to remove non-existing healthcheck";
    return false;
  }
  if (!config_.testing) {
    auto res = bpfAdapter_.bpfMapDeleteElement(
        bpfAdapter_.getMapFdByName("hc_reals_map"), &key);
    if (res) {
      LOG(INFO) << "can't remove hc w/ somark: " << key
                << ", error: " << folly::errnoStr(errno);
      lbStats_.bpfFailedCalls++;
      return false;
    }
  }
  hcReals_.erase(hc_iter);
  return true;
}

std::unordered_map<uint32_t, std::string> KatranLb::getHealthcheckersDst() {
  // would be empty map in case if enableHc_ is false
  std::unordered_map<uint32_t, std::string> hcs;
  for (const auto& hc : hcReals_) {
    hcs[hc.first] = hc.second.str();
  }
  return hcs;
}

const std::string KatranLb::getRealForFlow(const KatranFlow& flow) {
  if (config_.disableForwarding) {
    LOG(ERROR) << "getRealForFlow called on a non-forwarding instance";
    return kEmptyString.data();
  }
  if (!progsLoaded_) {
    LOG(ERROR) << "bpf programs are not loaded";
    return kEmptyString.data();
  }
  auto sim = KatranSimulator(getKatranProgFd());
  return sim.getRealForFlow(flow);
}

bool KatranLb::updateVipMap(
    const ModifyAction action,
    const VipKey& vip,
    vip_meta* meta) {
  auto vip_addr = IpHelpers::parseAddrToBe(vip.address);
  vip_definition vip_def = {};
  if ((vip_addr.flags & V6DADDR) > 0) {
    std::memcpy(vip_def.vipv6, vip_addr.v6daddr, 16);
  } else {
    vip_def.vip = vip_addr.daddr;
  }
  vip_def.port = folly::Endian::big(vip.port);
  vip_def.proto = vip.proto;
  if (action == ModifyAction::ADD) {
    auto res = bpfAdapter_.bpfUpdateMap(
        bpfAdapter_.getMapFdByName("vip_map"), &vip_def, meta);
    if (res != 0) {
      LOG(INFO) << "can't add new element into vip_map, error: "
                << folly::errnoStr(errno);
      lbStats_.bpfFailedCalls++;
      return false;
    }
  } else {
    auto res = bpfAdapter_.bpfMapDeleteElement(
        bpfAdapter_.getMapFdByName("vip_map"), &vip_def);
    if (res != 0) {
      LOG(INFO) << "can't delete element from vip_map, error: "
                << folly::errnoStr(errno);
      lbStats_.bpfFailedCalls++;
      return false;
    }
  }
  return true;
}

bool KatranLb::updateRealsMap(
    const folly::IPAddress& real,
    uint32_t num,
    uint8_t flags) {
  auto real_addr = IpHelpers::parseAddrToBe(real);
  flags &= ~V6DADDR; // to keep IPv4/IPv6 specific flag
  real_addr.flags |= flags;
  auto res = bpfAdapter_.bpfUpdateMap(
      bpfAdapter_.getMapFdByName("reals"), &num, &real_addr);
  if (res != 0) {
    LOG(INFO) << "can't add new real, error: " << folly::errnoStr(errno);
    lbStats_.bpfFailedCalls++;
    return false;
  } else {
    return true;
  }
};

void KatranLb::decreaseRefCountForReal(const folly::IPAddress& real) {
  auto real_iter = reals_.find(real);
  if (real_iter == reals_.end()) {
    return;
  }
  real_iter->second.refCount--;
  if (real_iter->second.refCount == 0) {
    auto num = real_iter->second.num;
    // no more vips using this real
    realNums_.push_back(num);
    reals_.erase(real_iter);
    numToReals_.erase(num);
  }
}

uint32_t KatranLb::increaseRefCountForReal(
    const folly::IPAddress& real,
    uint8_t flags) {
  auto real_iter = reals_.find(real);
  flags &= ~V6DADDR; // to keep IPv4/IPv6 specific flag
  if (real_iter != reals_.end()) {
    real_iter->second.refCount++;
    return real_iter->second.num;
  } else {
    if (realNums_.size() == 0) {
      return config_.maxReals;
    }
    RealMeta rmeta;
    auto rnum = realNums_[0];
    realNums_.pop_front();
    numToReals_[rnum] = real;
    rmeta.refCount = 1;
    rmeta.num = rnum;
    rmeta.flags = flags;
    reals_[real] = rmeta;
    if (!config_.testing) {
      updateRealsMap(real, rnum, flags);
    }
    return rnum;
  }
}

bool KatranLb::hasFeature(KatranFeatureEnum feature) {
  switch (feature) {
    case KatranFeatureEnum::LocalDeliveryOptimization:
      return features_.localDeliveryOptimization;
    case KatranFeatureEnum::DirectHealthchecking:
      return features_.directHealthchecking;
    case KatranFeatureEnum::GueEncap:
      return features_.gueEncap;
    case KatranFeatureEnum::InlineDecap:
      return features_.inlineDecap;
    case KatranFeatureEnum::Introspection:
      return features_.introspection;
    case KatranFeatureEnum::SrcRouting:
      return features_.srcRouting;
    case KatranFeatureEnum::FlowDebug:
      return features_.flowDebug;
  }
  folly::assume_unreachable();
}

bool KatranLb::installFeature(
    KatranFeatureEnum feature,
    const std::string& prog_path) {
  if (hasFeature(feature)) {
    LOG(INFO) << "already have requested feature";
    return true;
  }
  if (prog_path.empty()) {
    LOG(ERROR) << "failed to install feature: prog_path is empty";
    return false;
  }
  auto original_balancer_prog = config_.balancerProgPath;
  if (!reloadBalancerProg(prog_path)) {
    LOG(ERROR) << "failed to install feature: reloading prog failed";

    if (!reloadBalancerProg(original_balancer_prog)) {
      LOG(ERROR) << "failed to reload original balancer prog";
    }
    return false;
  }
  if (!config_.testing) {
    attachBpfProgs();
  }
  return hasFeature(feature);
}

bool KatranLb::removeFeature(
    KatranFeatureEnum feature,
    const std::string& prog_path) {
  if (!hasFeature(feature)) {
    return true;
  }
  if (prog_path.empty()) {
    return false;
  }
  auto original_balancer_prog = config_.balancerProgPath;
  if (!reloadBalancerProg(prog_path)) {
    LOG(ERROR) << "provided prog does not have wanted feature, "
               << "reverting by reloading original balancer prog";

    if (!reloadBalancerProg(original_balancer_prog)) {
      LOG(ERROR) << "failed to reload original balancer prog";
    }
    return false;
  }
  if (!config_.testing) {
    attachBpfProgs();
  }
  return !hasFeature(feature);
}

} // namespace katran
