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
#include <unordered_set>
#include <vector>

#include <folly/IPAddress.h>

#include "katran/lib/BalancerStructs.h"
#include "katran/lib/BpfAdapter.h"
#include "katran/lib/CHHelpers.h"
#include "katran/lib/IpHelpers.h"
#include "katran/lib/KatranLbStructs.h"
#include "katran/lib/KatranSimulator.h"
#include "katran/lib/MonitoringStructs.h"
#include "katran/lib/Vip.h"

namespace katran {

class KatranMonitor;

/**
 * position of elements inside control vector
 */
constexpr int kMacAddrPos = 0;
constexpr int kIpv4TunPos = 1;
constexpr int kIpv6TunPos = 2;
constexpr int kMainIntfPos = 3;
constexpr int kHcIntfPos = 4;
constexpr int kIntrospectionGkPos = 5;

/**
 * constants are from balancer_consts.h
 */
constexpr uint32_t kLruCntrOffset = 0;
constexpr uint32_t kLruMissOffset = 1;
constexpr uint32_t kLruFallbackOffset = 3;
constexpr uint32_t kIcmpTooBigOffset = 4;
constexpr uint32_t kLpmSrcOffset = 5;
constexpr uint32_t kInlineDecapOffset = 6;
constexpr uint32_t kQuicRoutingOffset = 7;
constexpr uint32_t kQuicCidVersionOffset = 8;
constexpr uint32_t kQuicCidDropOffset = 9;
constexpr uint32_t kTcpServerIdRoutingOffset = 10;

/**
 * LRU map related constants
 */
constexpr int kFallbackLruSize = 1024;
constexpr int kMapNoFlags = 0;
constexpr int kMapNumaNode = 4;
constexpr int kNoNuma = -1;

namespace {
/**
 * state of katran monitor forwarding. if it is disabled - forwarding
 * plane would never send anything to userspace through perfpipe
 */
enum class KatranMonitorState {
  DISABLED,
  ENABLED,
};

/**
 * Prog names
 */
constexpr folly::StringPiece kBalancerProgName = "xdp-balancer";
constexpr folly::StringPiece kHealthcheckerProgName = "cls-hc";
} // namespace

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
   * @return true on success
   *
   * helper function to reload balancer program in runtime
   * could throw std::invalid_argument if reload fails.
   */
  bool reloadBalancerProg(
      const std::string& path,
      folly::Optional<KatranConfig> config = folly::none);

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
   * @return std::map<int, uint32_t> of ifindex of configured interfaces
   *  where key is:
   *     { kIpv4TunPos(1), kIpv6TunPos(2), kMainIntfPos(3), kHcIntfPos(4) }
   *
   * helper function which returns ifindex of all the configured interfaces
   */
  std::map<int, uint32_t> getIndexOfNetworkInterfaces();

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
   * @param bool set flag; if true - set specified flag; unset otherwise
   * @return true on success
   *
   * helper function to change Vip's related flags (we are using this flags
   * to change behavior in forwarding path. e.g bypass lru or dont consider
   * src port in hash function)
   */
  bool modifyVip(const VipKey& vip, uint32_t flag, bool set = true);

  /**
   * @param VipKey vip to modify
   * @param HashFunction func to generate hash ring
   *
   * helper function to change hash ring's hash function
   */
  bool changeHashFunctionForVip(const VipKey& vip, HashFunction func);

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
   * @param std::string& real to modify
   * @param uint8_t flag to set/unset
   * @param bool set flag; if true - set specified flag; unset otherwise
   * @return true on success
   *
   * helper function to change Real's related flags
   */
  bool modifyReal(const std::string& real, uint8_t flags, bool set = true);

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
   * @param string address of the real
   * @return int64_t internal index of the real. -1 if does not exists
   *
   * helper function to get internal (to katran) index of real
   * could be used in other helpers. e.g. to get per real statistics.
   * if real does not exist index -1 would be returned.
   */
  int64_t getIndexForReal(const std::string& real);

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
   * @param vector<string> of source prefixes
   * @param string dst address where specified sources are going to be routed
   * @return int 0 on success, number of errors otherwise
   *
   * helper function to add src prefixes to destination mapping
   */
  int addSrcRoutingRule(
      const std::vector<std::string>& srcs,
      const std::string& dst);

  /**
   * @param vector<CIDRNetwork> of source prefixes
   * @param string dst address where specified sources are going to be routed
   * @return int 0 on success, number of errors otherwise
   *
   * helper function to add src prefixes to destination mapping
   */
  int addSrcRoutingRule(
      const std::vector<folly::CIDRNetwork>& srcs,
      const std::string& dst);

  /**
   * @param vector<string> of source prefixes
   * @return bool true if there was no fatal errors
   *
   * helper function to delete src prefixes to destination mapping
   */
  bool delSrcRoutingRule(const std::vector<std::string>& srcs);

  /**
   * @param vector<CIDRNetwork> of source prefixes
   * @return bool true if there was no fatal errors
   *
   * helper function to delete src prefixes to destination mapping
   */
  bool delSrcRoutingRule(const std::vector<folly::CIDRNetwork>& srcs);

  /**
   * @param string address for inline decapsulation
   * @return bool true on success
   *
   * helper function to add address, so all packets toward it would be
   * decapsulated in bpf context.
   */
  bool addInlineDecapDst(const std::string& dst);

  /**
   * @param string address for inline decapsulation
   * @return bool true on success
   *
   * helper function to delete address, which is used for inline
   * decapsulation
   */
  bool delInlineDecapDst(const std::string& dst);

  /**
   * @return vector<string> destanations
   *
   * helper function to get/query currently used destanations for inline
   * decapsulation
   */
  std::vector<std::string> getInlineDecapDst();

  /**
   * @return bool true if there was no fatal errors
   *
   * helper function to clear all source routing rules
   */
  bool clearAllSrcRoutingRules();

  /**
   * @return map<string,string> of src to dst mapping
   *
   * helper function to get all source to destination mappings
   */
  std::unordered_map<std::string, std::string> getSrcRoutingRule();

  /**
   * @return map<CIDRNetwork,string> of src to dst mapping
   *
   * helper function to get all source to destination mappings
   */
  std::unordered_map<folly::CIDRNetwork, std::string> getSrcRoutingRuleCidr();

  /**
   * @return const map<CIDRNetwork, uint32_t>& of src to dst mapping
   *
   * helper function to get const reference for internal source to destination
   * mapping.
   */
  const std::unordered_map<folly::CIDRNetwork, uint32_t>& getSrcRoutingMap() {
    return lpmSrcMapping_;
  }

  /**
   * @return const map<uint32_t, str>& of internal index to real mapping
   *
   * helper function to get internal index to real's ip address mapping.
   */
  const std::unordered_map<uint32_t, std::string> getNumToRealMap();

  /**
   * @return uint32_t number of src to dst mappings
   *
   * helper function to get current number of rules for source based routing
   */
  uint32_t getSrcRoutingRuleSize();

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
   * @return struct lb_stats w/ statistic of QUIC routing stats
   *
   * helper function which returns how many QUIC packets were routed
   * using the default 5-tuple hash vs using the connection-id
   */
  lb_stats getQuicRoutingStats();

  /**
   * @return struct lb_stats w/ statistic of QUIC CID versions stats
   *
   * helper function which returns how many QUIC packets were routed
   * using CIDv1 vs CIDv2
   */
  lb_stats getQuicCidVersionStats();

  /**
   * @return struct lb_stats w/ statistic of QUIC packet drop stats
   *
   * helper function which returns how many QUIC packets were dropped:
   * v1 - packets routed to real #0, because bpf array map defaults to 0,
   * unknown server ID result in routing to real #0, we don't currently
   * have way to distinguish between expected and unexpected cases.
   * v2 - packets dropped because server ID map pointed to unknown real ID.
   */
  lb_stats getQuicCidDropStats();

  /**
   * @return struct lb_stats w/ statistic of server_id based routing of
   * TCP packets (if enabled)
   *
   * helper function which returns how many TCP packets were routed
   * using the default 5-tuple hash vs using the connection-id
   */
  lb_stats getTcpServerIdRoutingStats();

  /**
   * @return struct lb_stats w/ src routing related statistics
   *
   * helper function which returns how many packets were sent to local
   * backends (v1) and how many matched lpm src rule and were sent to remote
   * destination (v2)
   */
  lb_stats getSrcRoutingStats();

  /**
   * @return struct lb_stats w/ src inline decapsulation statistics
   *
   * helper function which returns how many packets were decapsulated
   * inline (v1)
   */
  lb_stats getInlineDecapStats();

  /**
   * @param uint32_t index of the real
   * @return struct lb_stats w/ per real pps and bps statistics
   *
   * helper function which returns per real statistics for real with specified
   * index.
   */
  lb_stats getRealStats(uint32_t index);

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
    return bpfAdapter_.getProgFdByName(kBalancerProgName.toString());
  }

  /**
   * @return int fd of the healthchecker's bpf program
   * helper function to get fd of healthchecker bpf program
   */
  int getHealthcheckerProgFd() {
    return bpfAdapter_.getProgFdByName(kHealthcheckerProgName.toString());
  }

  /**
   * @return false if introspection is not enabled
   *
   * if katran introspection is enabled: stop all monitoring
   */
  bool stopKatranMonitor();

  /**
   * @param uint32_t limit how many packets are going to be written/collected
   * @return false if introspection is not enabled
   *
   * if katran introspection is enabled: restart katran monitoring. collected
   * packets are going to be written either into separate files or into buffer
   */
  bool restartKatranMonitor(
      uint32_t limit,
      folly::Optional<PcapStorageFormat> storage = folly::none);

  /**
   * @param monitoring::EventId event monitoring event id. see
   * introspection.h and MonitoringStructs.h
   * @return unique_ptr<IOBuf> on success or nullptr otherwise
   *
   * getKatranMonitorEventBuffer return iobuf which contains all the packets
   * for specified event. if event number was not defined or
   * PcapStorageFormat was not set to IOBUF nullptr would be returned.
   * This function is not thread safe. underlying IOBuf, when accessed while
   * monitoring is still running, could point to partially written packet
   */
  std::unique_ptr<folly::IOBuf> getKatranMonitorEventBuffer(
      monitoring::EventId event);

  /**
   * @return KatranMonitorStats stats from katran monitor
   *
   * if katran introspection is enabled: return stats from monitor. such as
   * "how many packets has been written/recved from forwarding plane" etc
   */
  KatranMonitorStats getKatranMonitorStats();

  /**
   * @return KatranLbStats generic stats about userspace part of katran
   *
   * helper function which helps to introspect internals of katran's
   * userspace counterpart
   */
  KatranLbStats getKatranLbStats() {
    return lbStats_;
  }

  /**
   * record packet level counters for relevant events in health-check program
   */
  HealthCheckProgStats getStatsForHealthCheckProgram();

  /**
   * @param map string name of the bpf map
   * @return KatranBpfMapStats struct holding the max and current entry count
   * Could throw std::runtime_error on failure
   */
  KatranBpfMapStats getBpfMapStats(const std::string& map);

  /**
   * @param KatranFlow 5 tuple which describes a flow
   * @return string address of the real.
   *
   * getRealForFlow functions returns address of the real where specified
   * 5 tuple is going to be sent.
   * returns empty string if given 5 tuple does not belong to a configured vip
   */
  const std::string getRealForFlow(const KatranFlow& flow);

  /**
   * @param src ip address of the src
   * @return true is the update is successful
   *
   * Adds source ip to be used by Katran when it encapsulates packet.
   * It replaces existing one if present for the IP of given type (v4 or v6)
   */
  bool addSrcIpForPcktEncap(const folly::IPAddress& src);

  /**
   * Get a shared pointer to the monitor
   *
   * This helps construct a monitoring service without upper layer handler
   * (i.e. KatranServiceHandler)
   */
  std::shared_ptr<KatranMonitor> getKatranMonitor() {
    return monitor_;
  }

  /**
   * Return if katran has certain feature
   */
  bool hasFeature(KatranFeatureEnum feature);

  /**
   * @param feature The feature requested to have
   * @param prog_path The prog to reload if the lb doesn't have the feature
   * @return true if the lb already has the feature, or obtained after
   * reloading, otherwise false
   *
   * Ask katran lb to install a certain feature. Lb might have to reload the
   * provided prog path if it's not available currently.
   */
  bool installFeature(
      KatranFeatureEnum feature,
      const std::string& prog_path = "");

  /**
   * @param feature The feature requested to not have
   * @param prog_path The prog to reload if the lb has the feature
   * @return true if the lb already doesn't have the feature, or lost after
   * reloading, otherwise false
   *
   * The opposite of instalFeature. Ask katran lb to remove a certain feature.
   * Lb might have to reload the provided prog path if it's present in the
   * current prog.
   */
  bool removeFeature(
      KatranFeatureEnum feature,
      const std::string& prog_path = "");

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
  bool
  updateRealsMap(const folly::IPAddress& real, uint32_t num, uint8_t flags = 0);

  /**
   * helper function to get stats from counter on specified possition
   */
  lb_stats getLbStats(uint32_t position, const std::string& map = "stats");

  /**
   * helper function to decrease real's ref count and delete it from
   * internal dicts if rec count became zero
   */
  void decreaseRefCountForReal(const folly::IPAddress& real);

  /**
   * helper function to add new real or increase ref count for existing one
   */
  uint32_t increaseRefCountForReal(
      const folly::IPAddress& real,
      uint8_t flags = 0);

  /**
   * helper function to do initial sanity checking right after bpf programs
   * has been loaded (e.g. to make sure that all maps which we are expecting
   * to see/use are exists etc)
   * throws on failure
   * @param flowDebug Check the validity of flow_debug_maps
   */
  void initialSanityChecking(bool flowDebug=false);

  /**
   * helper function to create/initialize LRUs.
   * we must init LRUs before we are going to load bpf program.
   * throws on failure
   * @param flowDebug Initialize flow_debug_maps/flow_debug_lru
   */
  void initLrus(bool flowDebug=false);

  /**
   * helper function to attach created LRUs. must be done after
   * bpf program is loaded.
   * throws on failure
   * @param flowDebug Attach the cpu-specific flow_debug_lru maps
   */
  void attachLrus(bool flowDebug=false);

  /**
   * helper function to enable everything related to introspection/events
   * reporting. it will set up perf pipe and all routines to read from them
   */
  void startIntrospectionRoutines();

  /**
   * helper function to creat LRU map w/ specified size.
   * returns fd on success, -1 on failure.
   */
  int createLruMap(
      int size = kFallbackLruSize,
      int flags = kMapNoFlags,
      int numaNode = kNoNuma);

  /**
   * helper function to creat LRU map w/ specified size.
   * returns fd on success, -1 on failure.
   */
  int createFlowDebugLru(
      int size = kFallbackLruSize,
      int flags = kMapNoFlags,
      int numaNode = kNoNuma);

  /**
   * create and save the fd of a map used for flow debugging
   * throws on failure
   */
  void initFlowDebugMapForCore(int core, int size, int flags, int numaNode);

  /**
   * create a prototype map for flow debugging
   * throws on failure
   */
  void initFlowDebugPrototypeMap();

  /**
   * sets the cpu-specific entry in the parent map
   * throws on failure
   */
  void attachFlowDebugLru(int core);

  /**
   * helper function which do forwarding plane feature discovering
   */
  void featureDiscovering();

  /**
   * helper function to validate that specified string is a valid ip address
   * (or network prefix if allowNetAddr is equal to true)
   */
  AddressType validateAddress(
      const std::string& addr,
      bool allowNetAddr = false);

  /**
   * helper function to add or remove src (string src) to dst (rnum; id of
   * real in numToReals_ structure) - used for source based
   * routing) to/from forwarding plane
   */
  bool modifyLpmSrcRule(
      ModifyAction action,
      const folly::CIDRNetwork& src,
      uint32_t rnum);

  /**
   * helper function to modify specified lpm map. convention is: all lpm maps
   * are named <map_prefix>_v4 or _v6. suffix would be automatically added by
   * this routine depending on addr's family.
   */
  bool modifyLpmMap(
      const std::string& lpmMapNamePrefix,
      ModifyAction action,
      const folly::CIDRNetwork& addr,
      void* value);

  /**
   * helper function to modify inline decap destanations map
   */
  bool modifyDecapDst(
      ModifyAction action,
      const folly::IPAddress& dst,
      const uint32_t flags = 0);

  /**
   * helper function to change state of katran monitor's forwarding
   */
  bool changeKatranMonitorForwardingState(KatranMonitorState state);

  /*
   * setupGueEnvironment prepare katran to run w/ GUE encap (e.g. setting up
   * src addresses for outer packets)
   */
  void setupGueEnvironment();

  /*
   * setupHcEnvironment prepare katran to run healthchecks (e.g. setting up
   * src addresses for outer packets)
   */
  void setupHcEnvironment();

  /**
   * enableRecirculation enables katran to use recirculation technics, where
   * some codepaths inside xdp forwarding plane, after packets monipulation,
   * rerun whole load balancer's code (e.g. after decapsulation). it is
   * acheaving this by register itself in internal programs array
   */
  void enableRecirculation();

  /**
   * program hash ring in forwarding plane
   */
  void programHashRing(
      const std::vector<RealPos>& chPositions,
      const uint32_t vipNum);

  /**
   * main configurations of katran
   */
  KatranConfig config_;

  /**
   * bpf adapter to program forwarding plane
   */
  BpfAdapter bpfAdapter_;

  /**
   * implements all introspection related routines
   */
  std::shared_ptr<KatranMonitor> monitor_{nullptr};

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
  std::unordered_map<uint32_t, folly::IPAddress> hcReals_;

  std::unordered_map<folly::IPAddress, RealMeta> reals_;

  /**
   * key: QUIC host id (from CID); value: real IP
   */
  std::unordered_map<uint32_t, folly::IPAddress> quicMapping_;
  /**
   * for reverse real's lookup. get real by num.
   * used when we are going to delete vip and coresponding reals.
   */
  std::unordered_map<uint32_t, folly::IPAddress> numToReals_;

  std::unordered_map<VipKey, Vip, VipKeyHasher> vips_;

  /**
   * map of src address to dst mapping. used for source based routing.
   */
  std::unordered_map<folly::CIDRNetwork, uint32_t> lpmSrcMapping_;

  /**
   * set of destantions, which are used for inline decapsulation.
   */
  std::unordered_set<folly::IPAddress> decapDsts_;

  /**
   * flag which indicates if katran is working in "standalone" mode or not.
   */
  bool standalone_;

  /**
   * fd of rootMap if katran is working in "shared" mode.
   */
  int rootMapFd_;

  /**
   * flag which indicates that bpf progs has been loaded.
   */
  bool progsLoaded_{false};

  /**
   * flag which indicates that bpf progs has been attached
   */
  bool progsAttached_{false};

  /**
   * enabled optional features
   */
  struct KatranFeatures features_;
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
   * vector of flow debug maps descriptors;
   */
  std::vector<int> flowDebugMapsFd_;

  /**
   * userspace library stats
   */
  KatranLbStats lbStats_;

  /**
   * flag which indicates that introspection routines already started
   */
  bool introspectionStarted_{false};

  /**
   * flag which indicates that bpf program was reloaded
   */
  bool progsReloaded_{false};
};

} // namespace katran
