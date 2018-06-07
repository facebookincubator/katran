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
#include <iterator>
#include <stdexcept>

#include <folly/Format.h>
#include <folly/IPAddress.h>
#include <folly/lang/Bits.h>
#include <glog/logging.h>

namespace katran {

namespace {
constexpr uint8_t V6DADDR = 1;
constexpr int kDeleteXdpProg = -1;
constexpr int kMacBytes = 6;
constexpr int kCtlMapSize = 16;
constexpr int kLruPrototypePos = 0;
constexpr int kMaxForwardingCores = 128;
constexpr int kFirstElem = 0;
constexpr uint32_t kMaxQuicId = 4095;
} // namespace

KatranLb::KatranLb(const KatranConfig& config)
    : maxVips_(config.maxVips),
      maxReals_(config.maxReals),
      chRingSize_(config.chRingSize),
      bpfAdapter_(!config.testing),
      tcPriority_(config.priority),
      balancerProgPath_(config.balancerProgPath),
      healthcheckingProgPath_(config.healthcheckingProgPath),
      rootMapPath_(config.rootMapPath),
      ctlValues_(kCtlMapSize),
      testing_(config.testing),
      standalone_(true),
      rootMapPos_(config.rootMapPos),
      enableHc_(config.enableHc),
      forwardingCores_(config.forwardingCores),
      numaNodes_(config.numaNodes),
      lruMapsFd_(kMaxForwardingCores),
      totalLruSize_(config.LruSize) {
  for (uint32_t i = 0; i < config.maxVips; i++) {
    vipNums_.push_back(i);
  }

  for (uint32_t i = 0; i < config.maxReals; i++) {
    realNums_.push_back(i);
  }

  if (!config.rootMapPath.empty()) {
    standalone_ = false;
  }
  if (!testing_) {
    ctl_value ctl;
    int res;

    // populating ctl vector
    if (config.defaultMac.size() != 6) {
      throw std::invalid_argument("mac's size is not equal to six byte");
    }
    for (int i = 0; i < 6; i++) {
      ctl.mac[i] = config.defaultMac[i];
    }
    ctlValues_[kMacAddrPos] = ctl;

    if (config.enableHc) {
      res = bpfAdapter_.getInterfaceIndex(config.v4TunInterface);
      if (!res) {
        throw std::invalid_argument("can't resolve ifindex for v4tun intf");
      }
      ctl.ifindex = res;
      ctlValues_[kIpv4TunPos] = ctl;

      res = bpfAdapter_.getInterfaceIndex(config.v6TunInterface);
      if (res == 0) {
        throw std::invalid_argument("can't resolve ifindex for v6tun intf");
      }
      ctl.ifindex = res;
      ctlValues_[kIpv6TunPos] = ctl;
    }

    res = bpfAdapter_.getInterfaceIndex(config.mainInterface);
    if (res == 0) {
      throw std::invalid_argument("can't resolve ifindex for main intf");
    }
    ctl.ifindex = res;
    ctlValues_[kMainIntfPos] = ctl;
  }
}

KatranLb::~KatranLb() {
  if (!testing_ && progsAttached_) {
    int res;
    auto mainIfindex = ctlValues_[kMainIntfPos].ifindex;
    if (standalone_) {
      res = bpfAdapter_.detachXdpProg(mainIfindex);
    } else {
      res = bpfAdapter_.bpfMapDeleteElement(rootMapFd_, &rootMapPos_);
    }
    if (res != 0) {
      LOG(INFO) << "wasn't able to delete main bpf prog";
    }
    if (enableHc_) {
      res = bpfAdapter_.deleteTcBpfFilter(
          getHealthcheckerProgFd(),
          mainIfindex,
          "katran-healthchecker",
          tcPriority_,
          BPF_TC_EGRESS);
      if (res != 0) {
        LOG(INFO) << "wasn't able to delete hc bpf prog";
      }
    }
  }
}

void KatranLb::initialSanityChecking() {
  int res;

  std::vector<std::string> maps = {"vip_map",
                                   "ch_rings",
                                   "reals",
                                   "stats",
                                   "ctl_array",
                                   "lru_maps_mapping",
                                   "quic_mapping"};

  res = getKatranProgFd();
  if (res < 0) {
    throw std::invalid_argument("can't get fd for prog: xdp-balancer");
  }

  if (enableHc_) {
    res = getHealthcheckerProgFd();
    if (res < 0) {
      throw std::invalid_argument("can't get fd for prog: cls-hc");
    }
    maps.push_back("hc_ctrl_map");
    maps.push_back("hc_reals_map");
  }

  // some sanity checking. we will check that all maps exists, so in later
  // code we wouldn't check if their fd != -1
  // names of the maps must be the same as in bpf code.
  for (auto& map : maps) {
    res = bpfAdapter_.getMapFdByName(map);
    if (res < 0) {
      VLOG(4) << "missing map: " << map;
      throw std::invalid_argument("map not found");
    }
  }
}

int KatranLb::createLruMap(int size, int flags, int numaNode) {
  return bpfAdapter_.createBpfMap(
      kBpfMapTypeLruHash,
      sizeof(struct flow_key),
      sizeof(struct real_pos_lru),
      size,
      flags,
      numaNode);
}

void KatranLb::initLrus() {
  bool forwarding_cores_specified{false};
  bool numa_mapping_specified{false};
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
    auto per_core_lru_size = totalLruSize_ / forwardingCores_.size();
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
      } else {
        numa_node = kNoNuma;
      }
      lru_fd = createLruMap(per_core_lru_size, kMapNumaNode, numa_node);
      if (lru_fd < 0) {
        LOG(FATAL) << "can't creat lru for core: " << core;
        throw std::runtime_error("cant create LRU for forwarding core");
      }
      lruMapsFd_[core] = lru_fd;
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
  res = bpfAdapter_.updateInnerMapsArray(kLruPrototypePos, lru_proto_fd);
  if (res < 0) {
    throw std::runtime_error(
        "can't update inner_maps_fds w/ prototype for main lru");
  }
}

void KatranLb::attachLrus() {
  if (!progsLoaded_) {
    throw std::runtime_error("can't attach lru when bpf progs are not loaded");
  }
  int map_fd, res, key;
  for (const auto& core : forwardingCores_) {
    key = core;
    map_fd = lruMapsFd_[core];
    res = bpfAdapter_.bpfUpdateMap(
        bpfAdapter_.getMapFdByName("lru_maps_mapping"), &key, &map_fd);
    if (res < 0) {
      throw std::runtime_error("cant attach lru to forwarding core");
    }
  }
}

void KatranLb::loadBpfProgs() {
  int res;
  initLrus();
  // loading bpf progs.
  res = bpfAdapter_.loadBpfProg(balancerProgPath_);
  if (res) {
    throw std::invalid_argument("can't load main bpf prog");
  }

  if (enableHc_) {
    res = bpfAdapter_.loadBpfProg(healthcheckingProgPath_);
    if (res) {
      throw std::invalid_argument("can't load healthchecking bpf prog");
    }
  }

  initialSanityChecking();

  // add values to main prog ctl_array
  std::vector<uint32_t> balancer_ctl_keys = {kMacAddrPos};

  for (auto ctl_key : balancer_ctl_keys) {
    res = bpfAdapter_.bpfUpdateMap(
        bpfAdapter_.getMapFdByName("ctl_array"),
        &ctl_key,
        &ctlValues_[ctl_key]);

    if (res != 0) {
      throw std::invalid_argument("can't update ctl array for main prog");
    }
  }

  if (enableHc_) {
    std::vector<uint32_t> hc_ctl_keys = {kIpv4TunPos, kIpv6TunPos};

    for (auto ctl_key : hc_ctl_keys) {
      res = bpfAdapter_.bpfUpdateMap(
          bpfAdapter_.getMapFdByName("hc_ctrl_map"),
          &ctl_key,
          &ctlValues_[ctl_key].ifindex);

      if (res != 0) {
        throw std::invalid_argument("can't update ctrl map for hc prog");
      }
    }
  }
  progsLoaded_ = true;
  attachLrus();
}

void KatranLb::attachBpfProgs() {
  if (!progsLoaded_) {
    throw std::invalid_argument("failed to attach bpf progs: progs not loaded");
  }
  int res;
  auto main_fd = bpfAdapter_.getProgFdByName("xdp-balancer");
  auto interface_index = ctlValues_[kMainIntfPos].ifindex;
  if (standalone_) {
    // attaching main bpf prog in standalone mode
    res = bpfAdapter_.modifyXdpProg(main_fd, interface_index);
    if (res != 0) {
      throw std::invalid_argument(
          "can't attach main bpf prog "
          "to main inteface");
    }
  } else {
    // we are in "shared" mode and must register ourself in root xdp prog
    rootMapFd_ = bpfAdapter_.getPinnedBpfObject(rootMapPath_);
    if (rootMapFd_ < 0) {
      throw std::invalid_argument("can't get fd of xdp's root map");
    }
    res = bpfAdapter_.bpfUpdateMap(rootMapFd_, &rootMapPos_, &main_fd);
    if (res) {
      throw std::invalid_argument("can't register in root array");
    }
  }

  if (enableHc_) {
    // attaching healthchecking bpf prog.
    auto hc_fd = getHealthcheckerProgFd();
    res = bpfAdapter_.addTcBpfFilter(
        hc_fd,
        interface_index,
        "katran-healthchecker",
        tcPriority_,
        BPF_TC_EGRESS);
    if (res != 0) {
      if (standalone_) {
        // will try to remove main bpf prog.
        bpfAdapter_.detachXdpProg(interface_index);
      } else {
        bpfAdapter_.bpfMapDeleteElement(rootMapFd_, &rootMapPos_);
      }
      throw std::invalid_argument(
          "can't attach healthchecking bpf prog "
          "to main inteface");
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
  if (!testing_) {
    auto res = bpfAdapter_.bpfUpdateMap(
        bpfAdapter_.getMapFdByName("ctl_array"),
        &key,
        &ctlValues_[kMacAddrPos].mac);
    if (res != 0) {
      VLOG(4) << "can't add new mac address";
      return false;
    }
  }
  return true;
}

std::vector<uint8_t> KatranLb::getMac() {
  return std::vector<uint8_t>(
      std::begin(ctlValues_[kMacAddrPos].mac),
      std::end(ctlValues_[kMacAddrPos].mac));
}

bool KatranLb::addVip(const VipKey& vip, const uint32_t flags) {
  if (!folly::IPAddress::validate(vip.address)) {
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
  vips_.emplace(vip, Vip(vip_num, flags, chRingSize_));
  if (!testing_) {
    vip_meta meta;
    meta.vip_num = vip_num;
    meta.flags = flags;
    updateVipMap(ModifyAction::ADD, vip, &meta);
  }
  return true;
}

bool KatranLb::delVip(const VipKey& vip) {
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
  if (!testing_) {
    updateVipMap(ModifyAction::DEL, vip);
  }
  vips_.erase(vip_iter);
  return true;
}

std::vector<VipKey> KatranLb::getAllVips() {
  std::vector<VipKey> vips(vips_.size());
  int i = 0;
  for (auto& vip : vips_) {
    vips[i++] = vip.first;
  }
  return vips;
}

uint32_t KatranLb::getVipFlags(const VipKey& vip) {
  auto vip_iter = vips_.find(vip);
  if (vip_iter == vips_.end()) {
    throw std::invalid_argument("trying to get flags from non-existing vip");
  }
  return vip_iter->second.getVipFlags();
}

bool KatranLb::modifyVip(const VipKey& vip, uint32_t flag, bool set) {
  LOG(INFO) << folly::format(
      "modyfing vip: {}:{}:{}", vip.address, vip.port, vip.proto);

  auto vip_iter = vips_.find(vip);
  if (vip_iter == vips_.end()) {
    LOG(INFO) << "trying to modify non-existing vip";
    return false;
  }
  if (set) {
    vip_iter->second.setVipFlags(flag);
  } else {
    vip_iter->second.unsetVipFlags(flag);
  }
  if (!testing_) {
    vip_meta meta;
    meta.vip_num = vip_iter->second.getVipNum();
    meta.flags = vip_iter->second.getVipFlags();
    return updateVipMap(ModifyAction::ADD, vip, &meta);
  }
  return true;
}

bool KatranLb::addRealForVip(const NewReal& real, const VipKey& vip) {
  std::vector<NewReal> reals;
  reals.push_back(real);
  return modifyRealsForVip(ModifyAction::ADD, reals, vip);
}

bool KatranLb::delRealForVip(const NewReal& real, const VipKey& vip) {
  std::vector<NewReal> reals;
  reals.push_back(real);
  return modifyRealsForVip(ModifyAction::DEL, reals, vip);
}

bool KatranLb::modifyRealsForVip(
    const ModifyAction action,
    const std::vector<NewReal>& reals,
    const VipKey& vip) {
  UpdateReal ureal;
  std::vector<UpdateReal> ureals;
  ureal.action = action;

  auto vip_iter = vips_.find(vip);
  if (vip_iter == vips_.end()) {
    LOG(INFO) << "trying to modify reals for non existing vip";
    return false;
  }
  auto cur_reals = vip_iter->second.getReals();
  for (auto& real : reals) {
    if (!folly::IPAddress::validate(real.address)) {
      LOG(ERROR) << "Invalid real's address: " << real.address;
      continue;
    }
    VLOG(4) << folly::format(
        "modifying real: {} with weight {} for vip {}:{}:{}",
        real.address,
        real.weight,
        vip.address,
        vip.port,
        vip.proto);

    if (action == ModifyAction::DEL) {
      auto real_iter = reals_.find(real.address);
      if (real_iter == reals_.end()) {
        LOG(INFO) << "trying to delete non-existing real";
        continue;
      }
      if (std::find(
              cur_reals.begin(), cur_reals.end(), real_iter->second.num) ==
          cur_reals.end()) {
        // this real doesn't belong to this vip
        LOG(INFO) << "trying to delete non-existing real for the VIP";
        continue;
      }
      ureal.updatedReal.num = real_iter->second.num;
      decreaseRefCountForReal(real.address);
    } else {
      auto real_iter = reals_.find(real.address);
      if (real_iter != reals_.end()) {
        if (std::find(
                cur_reals.begin(), cur_reals.end(), real_iter->second.num) ==
            cur_reals.end()) {
          // increment ref count if it's a new real for this vip
          increaseRefCountForReal(real.address);
          cur_reals.push_back(real_iter->second.num);
        }
        ureal.updatedReal.num = real_iter->second.num;
      } else {
        auto rnum = increaseRefCountForReal(real.address);
        if (rnum == maxReals_) {
          LOG(INFO) << "exhausted real's space";
          continue;
        }
        ureal.updatedReal.num = rnum;
      }
      ureal.updatedReal.weight = real.weight;
      ureal.updatedReal.hash = folly::IPAddress(real.address).hash();
    }
    ureals.push_back(ureal);
  }

  auto ch_positions = vip_iter->second.batchRealsUpdate(ureals);
  auto vip_num = vip_iter->second.getVipNum();
  if (!testing_) {
    auto ch_fd = bpfAdapter_.getMapFdByName("ch_rings");
    uint32_t key;
    int res;
    for (auto pos : ch_positions) {
      key = vip_num * chRingSize_ + pos.pos;
      res = bpfAdapter_.bpfUpdateMap(ch_fd, &key, &pos.real);
      if (res != 0) {
        LOG(INFO) << "can't update ch ring";
      }
    }
  }
  return true;
}

std::vector<NewReal> KatranLb::getRealsForVip(const VipKey& vip) {
  auto vip_iter = vips_.find(vip);
  if (vip_iter == vips_.end()) {
    throw std::invalid_argument("trying to get real from non-existing vip");
  }
  auto vip_reals_ids = vip_iter->second.getRealsAndWeight();
  std::vector<NewReal> reals(vip_reals_ids.size());
  int i = 0;
  for (auto real_id : vip_reals_ids) {
    reals[i].weight = real_id.weight;
    reals[i].address = numToReals_[real_id.num];
    ++i;
  }
  return reals;
}

void KatranLb::modifyQuicRealsMapping(
    const ModifyAction action,
    const std::vector<QuicReal>& reals) {
  std::unordered_map<uint32_t, uint32_t> to_update;
  QuicReal qreal;
  for (auto& real : reals) {
    if (!folly::IPAddress::validate(real.address)) {
      LOG(ERROR) << "Invalid quic real's address: " << real.address;
      continue;
    }
    if (real.id > kMaxQuicId) {
      LOG(ERROR) << "trying to add mapping for id out of assigned space";
      continue;
    }
    VLOG(4) << folly::sformat("modifying quic's real {}", real.address);
    auto real_iter = quicMapping_.find(real.address);
    if (action == ModifyAction::DEL) {
      if (real_iter == quicMapping_.end()) {
        LOG(ERROR) << folly::sformat(
            "trying to delete nonexisting mapping for address {}",
            real.address);
        continue;
      }
      decreaseRefCountForReal(real.address);
      quicMapping_.erase(real_iter);
    } else {
      if (real_iter != quicMapping_.end()) {
        LOG(INFO) << folly::sformat(
            "trying to add already existing mapping for {}", real.address);
        // or we could silently delete old mapping instead.
        continue;
      }
      auto rnum = increaseRefCountForReal(real.address);
      if (rnum == maxReals_) {
        LOG(ERROR) << "exhausted real's space";
        continue;
      }
      to_update[real.id] = rnum;
      quicMapping_[real.address] = real.id;
    }
  }
  if (!testing_) {
    auto quic_mapping_fd = bpfAdapter_.getMapFdByName("quic_mapping");
    uint32_t id, rnum;
    int res;
    for (auto& mapping : to_update) {
      id = mapping.first;
      rnum = mapping.second;
      res = bpfAdapter_.bpfUpdateMap(quic_mapping_fd, &id, &rnum);
      if (res != 0) {
        LOG(ERROR) << "can't update quic mapping";
      }
    }
  }
}

std::vector<QuicReal> KatranLb::getQuicRealsMapping() {
  std::vector<QuicReal> reals;
  QuicReal real;
  for (auto& mapping : quicMapping_) {
    real.address = mapping.first;
    real.id = mapping.second;
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
  return getLbStats(maxVips_ + kLruCntrOffset);
}

lb_stats KatranLb::getLruMissStats() {
  return getLbStats(maxVips_ + kLruMissOffset);
}

lb_stats KatranLb::getLruFallbackStats() {
  return getLbStats(maxVips_ + kLruFallbackOffset);
}

lb_stats KatranLb::getIcmpTooBigStats() {
  return getLbStats(maxVips_ + kIcmpTooBigOffset);
}

lb_stats KatranLb::getLbStats(uint32_t position) {
  unsigned int nr_cpus = sysconf(_SC_NPROCESSORS_CONF);
  lb_stats stats[nr_cpus];
  lb_stats sum_stat = {};

  if (!testing_) {
    auto res = bpfAdapter_.bpfMapLookupElement(
        bpfAdapter_.getMapFdByName("stats"), &position, stats);
    if (!res) {
      for (auto& stat : stats) {
        sum_stat.v1 += stat.v1;
        sum_stat.v2 += stat.v2;
      }
    }
  }
  return sum_stat;
}

bool KatranLb::addHealthcheckerDst(
    const uint32_t somark,
    const std::string& dst) {
  if (!enableHc_) {
    return false;
  }
  if (!folly::IPAddress::validate(dst)) {
    LOG(ERROR) << "Invalid healthcheck's destanation: " << dst;
    return false;
  }
  VLOG(4) << folly::format(
      "adding healtcheck with so_mark {} to dst {}", somark, dst);

  uint32_t key = somark;
  beaddr addr;

  auto hc_iter = hcReals_.find(somark);
  if (hc_iter == hcReals_.end() && hcReals_.size() == maxReals_) {
    LOG(INFO) << "healthchecker's reals space exhausted";
    return false;
  }
  folly::IPAddress dst_addr(dst);
  // for md bassed tunnels remote_ipv4 must be in host endian format
  // and v6 in be
  if (dst_addr.isV4()) {
    addr = IpHelpers::parseAddrToInt(dst);
  } else {
    addr = IpHelpers::parseAddrToBe(dst);
  }
  if (!testing_) {
    auto res = bpfAdapter_.bpfUpdateMap(
        bpfAdapter_.getMapFdByName("hc_reals_map"), &key, &addr);
    if (res != 0) {
      LOG(INFO) << "can't add new real for healthchecking";
      return false;
    }
  }
  hcReals_[somark] = dst;
  return true;
}

bool KatranLb::delHealthcheckerDst(const uint32_t somark) {
  if (!enableHc_) {
    return false;
  }
  VLOG(4) << folly::format("deleting healtcheck with so_mark {}", somark);

  uint32_t key = somark;

  auto hc_iter = hcReals_.find(somark);
  if (hc_iter == hcReals_.end()) {
    LOG(INFO) << "trying to remove non-existing healthcheck";
    return false;
  }
  if (!testing_) {
    auto res = bpfAdapter_.bpfMapDeleteElement(
        bpfAdapter_.getMapFdByName("hc_reals_map"), &key);
    if (res) {
      LOG(INFO) << "can't remove hc w/ somark: " << key;
      return false;
    }
  }
  hcReals_.erase(hc_iter);
  return true;
}

std::unordered_map<uint32_t, std::string> KatranLb::getHealthcheckersDst() {
  // would be empty map in case if enableHc_ is false
  std::unordered_map<uint32_t, std::string> hcs(hcReals_);
  return hcs;
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
      LOG(INFO) << "can't add new element into vip_map";
      return false;
    }
  } else {
    auto res = bpfAdapter_.bpfMapDeleteElement(
        bpfAdapter_.getMapFdByName("vip_map"), &vip_def);
    if (res != 0) {
      LOG(INFO) << "can't delete element from vip_map";
      return false;
    }
  }
  return true;
}

bool KatranLb::updateRealsMap(const std::string& real, uint32_t num) {
  auto real_addr = IpHelpers::parseAddrToBe(real);
  auto res = bpfAdapter_.bpfUpdateMap(
      bpfAdapter_.getMapFdByName("reals"), &num, &real_addr);
  if (res != 0) {
    LOG(INFO) << "can't add new real";
    return false;
  } else {
    return true;
  }
};

void KatranLb::decreaseRefCountForReal(const std::string& real) {
  auto real_iter = reals_.find(real);
  if (real_iter == reals_.end()) {
    // it's expected that caller must call this function only after explicit
    // test that real exists. but we will double check it here
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

uint32_t KatranLb::increaseRefCountForReal(const std::string& real) {
  auto real_iter = reals_.find(real);
  if (real_iter != reals_.end()) {
    real_iter->second.refCount++;
    return real_iter->second.num;
  } else {
    if (realNums_.size() == 0) {
      return maxReals_;
    }
    RealMeta rmeta;
    auto rnum = realNums_[0];
    realNums_.pop_front();
    numToReals_[rnum] = real;
    rmeta.refCount = 1;
    rmeta.num = rnum;
    reals_[real] = rmeta;
    if (!testing_) {
      updateRealsMap(real, rnum);
    }
    return rnum;
  }
}

} // namespace katran
