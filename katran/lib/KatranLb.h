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
#include <deque>
#include <string>
#include <unordered_map>
#include <vector>

#include "katran/lib/BalancerStructs.h"
#include "katran/lib/BpfAdapter.h"
#include "katran/lib/CHHelpers.h"
#include "katran/lib/IpHelpers.h"
#include "katran/lib/KatranLbStructs.h"
#include "katran/lib/Vip.h"

namespace katran {

/**
 * position of elements inside control vector
 */
constexpr int kMacAddrPos = 0;
constexpr int kIpv4TunPos = 1;
constexpr int kIpv6TunPos = 2;
constexpr int kMainIntfPos = 3;

/**
 * constants are from balancer_consts.h
 */
constexpr uint32_t kLruCntrOffset = 0;
constexpr uint32_t kLruMissOffset = 1;
constexpr uint32_t kLruFallbackOffset = 3;
constexpr uint32_t kIcmpTooBigOffset = 4;

/**
 * LRU map related constants
 */
constexpr int kFallbackLruSize = 1024;
constexpr int kMapNoFlags = 0;
constexpr int kMapNumaNode = 4;
constexpr int kNoNuma = -1;

/**
 * This class implements all routines to interact with katran load balancer
 */
class KatranLb {
 public:
  KatranLb() = delete;
  /**
   * @param KatranConfig config main configuration of Katran load balancer
   */
  explicit KatranLb(const KatranConfig& config);

  ~KatranLb();

  /**
   * helper function to load bpf programs (lb and hc) in kernel
   * could throw std::invalid_argument if load fails.
   */
  void loadBpfProgs();

  /**
   * helper function to attach bpf program (e.g. to rootlet array,
   * driver or into tc qdisc)
   * could throw std::invalid_argument if load fails.
   */
  void attachBpfProgs();

  /**
   * @param std::vector<uint8_t> newMac for default router
   * @return true on success
   *
   * helper function to change mac address of default router,
   * where we are going to forward all the packets
   */
  bool changeMac(const std::vector<uint8_t> newMac);

  /**
   * @return std::vector<uint8_t> mac address of current default router
   *
   * helper function which returns current mac of defeault router which is
   * beeing used by a load balancer
   */
  std::vector<uint8_t> getMac();

  /**
   * @param VipKey& vip to be added
   * @param uint32_t flags for the new vip (such as no_port etc)
   * @return true on success
   *
   * helper function to add new vip. it returns false if maximum number of
   * vips has been reached.
   * could throw if specified address can't be parsed to v4 or v6
   */
  bool addVip(const VipKey& vip, const uint32_t flags = 0);

  /**
   * @param VipKey& vip
   * @return true on success
   *
   * helper function to delete vip
   */
  bool delVip(const VipKey& vip);

  /**
   * @return std::vector<VipKey> currently configured vips
   *
   * helper function which returns all currently configured vips
   */
  std::vector<VipKey> getAllVips();

  /**
   * @param VipKey vip to modify
   * @param uint32_t flag to set/unset
   * @param bool set flag; if true - set specified flag; unset othewise
   * @return true on success
   *
   * helper function to change Vip's related flags (we are using this flags
   * to change behavior in forwarding path. e.g bypass lru or dont consider
   * src port in hash function)
   */
  bool modifyVip(const VipKey& vip, uint32_t flag, bool set = true);

  /**
   * @param VipKey vip to get flags from
   * @return uint32_t flags of this vip
   *
   * helper function to return flags of specified vip
   * could throw if specified vip doesn't exist
   */
  uint32_t getVipFlags(const VipKey& vip);

  /**
   * @param NewReal& real to be added
   * @param VipKey& vip to which we want to add new real
   * @return true on sucess
   *
   * helper function which add's specified real to specified vip.
   * returns false if specified vip doesnt exists.
   * could throw if real's address cant be parsed to v4 or v6
   */
  bool addRealForVip(const NewReal& real, const VipKey& vip);

  /**
   * @param NewReal real to be deleted
   * @param VipKey vip from which we want to delete specified real
   * @return true on success
   *
   * helper function to remove specified real from vip.
   * returns true if real doesnt exist for specified vip (nop is not an error)
   */
  bool delRealForVip(const NewReal& real, const VipKey& vip);

  /**
   * @param ModifyAction action. either ADD or DEL
   * @param std::vector<NewReal> reals to be modified
   * @param VipKey vip for which we are going to modify specified reals
   * @return true on success
   *
   * helper function to add or delete reals for specified vip in batch
   * could throw if we will try to add real with address, which can't be
   * parsed to v4 or v6
   */
  bool modifyRealsForVip(
      const ModifyAction action,
      const std::vector<NewReal>& reals,
      const VipKey& vip);

  /**
   * @param VipKey vip to get reals from
   * @return std::vector<NewReal> currently configured reals for vip
   *
   * helper function, which returns currently configured reals for vip
   * and theirs weight
   * could throw if specified vip doesn't exist
   */
  std::vector<NewReal> getRealsForVip(const VipKey& vip);

  /**
   * @param ModifyAction action. either ADD or DEL
   * @param std::vector<QuicReal> reals to be modified
   *
   * helper function to add or delete mapping between quic's connection id
   * and real's ip address.
   */
  void modifyQuicRealsMapping(
      const ModifyAction action,
      const std::vector<QuicReal>& reals);

  /**
   * @return std::vector<QuicReal> currently configured mapping for quic
   *
   * helper function, which returns currently configured mapping
   * between quic's connection id and real's address
   */
  std::vector<QuicReal> getQuicRealsMapping();

  /**
   * @param VipKey vip
   * @return struct lb_stats w/ statistic for specified vip
   *
   * helper function which return total ammount of pkts and bytes which
   * has been sent to specified vip. it's up to external entity to calculate
   * actual speed in pps/bps
   */
  lb_stats getStatsForVip(const VipKey& vip);

  /**
   * @return struct lb_stats w/ statistics for lru misses
   *
   * helper function which returns total amount of processed packets and
   * how much of em was lru misses (when we wasnt able to find entry in
   * connection table)
   */
  lb_stats getLruStats();

  /**
   * @return struct lb_stats w/ statistic of the reasons for lru misses
   *
   * helper function which returns total amount of tcp lru misses because of
   * the tcp syns (v1) or non-syns (v2)
   */
  lb_stats getLruMissStats();

  /**
   * @return struct lb_stats w/ statistic of fallback lru hits
   *
   * helper function which return total amount of numbers when we fel back
   * to fallback_lru (v1);
   */
  lb_stats getLruFallbackStats();

  /**
   * @return struct lb_stats w/ statistic of icmp packet too big packets
   *
   * helper function which returns how many icmpv4/icmpv6 packet too big
   * has been generated after we have received packet, which is bigger then
   * maximum supported size.
   */
  lb_stats getIcmpTooBigStats();

  /**
   * @param uint32_t somark of the packet
   * @param std::string dst for a packed w/ specified so_mark
   * @return bool true on success
   *
   * helper function which add forwarding path for packets w/ specified
   * so_mark (all packet w/ this so_mark will be ip(6)ip(6) tunneled
   * to the dst)
   * could throw if dst can't be parsed to v4 or v6
   */
  bool addHealthcheckerDst(const uint32_t somark, const std::string& dst);

  /**
   * @param uint32_t somark to be deleted
   * @return bool true on success
   *
   * helper function which removes forwarding path for packets w/ specified
   * somark. returns false if specified somark doesnt exists
   */
  bool delHealthcheckerDst(const uint32_t somark);

  /**
   * @return unordered_map<uint32_t, string> dict of healthchecks
   *
   * return map of currently configured healthchecking marks and their dst
   */
  std::unordered_map<uint32_t, std::string> getHealthcheckersDst();

  /**
   * @return int fd of the katran's bpf program
   * helper function to get fd of katran bpf program
   */
  int getKatranProgFd() {
    return bpfAdapter_.getProgFdByName("xdp-balancer");
  };

  /**
   * @return int fd of the healthchecker's bpf program
   * helper function to get fd of healthchecker bpf program
   */
  int getHealthcheckerProgFd() {
    return bpfAdapter_.getProgFdByName("cls-hc");
  };

 private:
  /**
   * update vipmap(add or remove vip) in forwarding plane
   */
  bool updateVipMap(
      const ModifyAction action,
      const VipKey& vip,
      vip_meta* meta = nullptr);

  /**
   * update(add or remove) reals map in forwarding plane
   */
  bool updateRealsMap(const std::string& real, uint32_t num);

  /**
   * helper function to get stats from counter on specified possition
   */
  lb_stats getLbStats(uint32_t position);

  /**
   * helper function to decrease real's ref count and delete it from
   * internal dicts if rec count became zero
   */
  void decreaseRefCountForReal(const std::string& real);

  /**
   * helper function to add new real or increase ref count for existing one
   */
  uint32_t increaseRefCountForReal(const std::string& real);

  /**
   * helper function to do initial sanity checking right after bpf programs
   * has been loaded (e.g. to make sure that all maps which we are expecting
   * to see/use are exists etc)
   * throws on failure
   */
  void initialSanityChecking();

  /**
   * helper function to create/initialize LRUs.
   * we must init LRUs before we are going to load bpf program.
   * throws on failure
   */
  void initLrus();

  /**
   * helper function to attach created LRUs. must be done after
   * bpf program is loaded.
   * throws on failure
   */
  void attachLrus();

  /**
   * helper function to creat LRU map w/ specified size.
   * returns fd on success, -1 on failure.
   */
  int createLruMap(
      int size = kFallbackLruSize,
      int flags = kMapNoFlags,
      int numaNode = kNoNuma);

  /**
   * maximum amount of vips, which katran supports (must be the same number as
   * in forwarding plane (compiled xdp prog))
   */
  uint32_t maxVips_;

  /**
   * maximum ammount of reals,  which katran supports (must be the same number
   * as in forwarding plane).
   */
  uint32_t maxReals_;

  /**
   * size of ch ring (must be the same number as in forwarding plane).
   */
  uint32_t chRingSize_;

  /**
   * bpf adapter to program forwarding plane
   */
  BpfAdapter bpfAdapter_;

  /**
   * priority of tc prog for healthchecking
   */
  uint32_t tcPriority_;

  /**
   * path to bpf code for main balancer program
   */
  std::string balancerProgPath_;

  /**
   * path to bpf code for healthchecking
   */
  std::string healthcheckingProgPath_;

  /**
   * path to rootlet's pinned prog array
   */
  std::string rootMapPath_;

  /**
   * vector of unused possitions for vips and reals. for each element
   * we are going to pop position's num from the vector. for deleted one -
   * push it back (so it could be reused in future)
   */
  std::deque<uint32_t> vipNums_;
  std::deque<uint32_t> realNums_;

  /**
   * vector of control elements (such as default's mac; ifindexes etc)
   */
  std::vector<ctl_value> ctlValues_;

  /**
   * dict of so_mark to real mapping; for healthchecking
   */
  std::unordered_map<uint32_t, std::string> hcReals_;

  std::unordered_map<std::string, RealMeta> reals_;
  std::unordered_map<std::string, uint32_t> quicMapping_;
  /**
   * for reverse real's lookup. get real by num.
   * used when we are going to delete vip and coresponding reals.
   */
  std::unordered_map<uint32_t, std::string> numToReals_;

  std::unordered_map<VipKey, Vip, VipKeyHasher> vips_;

  /**
   * flag for testing. if set to true - we wont program forwarding path.
   */
  bool testing_;

  /**
   * flag which indicates if katran is working in "standalone" mode or not.
   */
  bool standalone_;

  /**
   * fd of rootMap if katran is working in "shared" mode.
   */
  int rootMapFd_;

  /**
   * poisition inside rootMapFd_ if we are in "shared" mode
   */
  uint32_t rootMapPos_;

  /**
   * flag, which indicates should we load healtcheck related routines or not
   */
  bool enableHc_;

  /**
   * flag which indicates that bpf progs has been loaded.
   */
  bool progsLoaded_{false};

  /**
   * flag which indicates that bpf progs has been attached
   */
  bool progsAttached_{false};

  /**
   * vector of forwarding CPUs (cpus/cores which are responisible for NICs
   * irq handling)
   */
  std::vector<int32_t> forwardingCores_;

  /**
   * optional vector, which contains mapping of forwarding cores to NUMA numa
   * length of this vector must be either zero (in this case we don't use it)
   * or equal to the length of forwardingCores_
   */
  std::vector<int32_t> numaNodes_;

  /**
   * vector of LRU maps descriptors;
   */
  std::vector<int> lruMapsFd_;

  /**
   * total LRUs map size; each forwarding cpu/core will have
   * total_size/forwarding_cores entries
   */
  uint64_t totalLruSize_;
};

} // namespace katran
