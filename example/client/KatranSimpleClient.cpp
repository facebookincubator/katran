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
#include <string>
#include <vector>

#include <folly/Conv.h>
#include <folly/Format.h>
#include <folly/IPAddress.h>
#include <folly/String.h>
#include <folly/init/Init.h>
#include <re2/re2.h>
#include <folly/io/async/AsyncSocket.h>
#include <thrift/lib/cpp2/async/HeaderClientChannel.h>

#include "KatranSimpleClient.h"

using namespace apache::thrift;
using namespace apache::thrift::protocol;
using namespace apache::thrift::transport;
using apache::thrift::HeaderClientChannel;
using folly::AsyncSocket;

namespace {
constexpr uint64_t IPPROTO_TCP = 6;
constexpr uint64_t IPPROTO_UDP = 17;
constexpr uint64_t DEFAULT_FLAG = 0;
constexpr uint64_t NO_SPORT = 1;
constexpr uint64_t NO_LRU = 2;
constexpr uint64_t QUIC_VIP = 4;
constexpr uint64_t DPORT_HASH = 8;
constexpr uint64_t LOCAL_VIP = 32;
constexpr uint32_t LOCAL_REAL = 2;

const std::map<std::string, uint64_t> vipFlagTranslationTable = {
    {"", DEFAULT_FLAG},     {"NO_SPORT", NO_SPORT},     {"NO_LRU", NO_LRU},
    {"QUIC_VIP", QUIC_VIP}, {"DPORT_HASH", DPORT_HASH}, {"LOCAL_VIP", LOCAL_VIP},
};
const std::map<std::string, uint32_t> realFlagTranslationTable = {
  {"LOCAL_REAL", LOCAL_REAL},
};
}; // namespace

namespace lb {
namespace katran {

KatranSimpleClient::KatranSimpleClient(const std::string &host, int port)
    : host_(host), port_(port) {
  auto addr = folly::SocketAddress(host_, port_);
  client_ = createKatranClient(addr);
}

void KatranSimpleClient::changeMac(const std::string &mac) {
  Mac newMac;
  newMac.mac = mac;
  if (client_->sync_changeMac(std::move(newMac))) {
    LOG(INFO) << folly::sformat("Mac address changed to {}.", mac);
  } else {
    LOG(ERROR) << "ERROR: Mac address could not be changed.";
  }
}

void KatranSimpleClient::getMac() {
  ::lb::katran::Mac mac;
  client_->sync_getMac(mac);
  LOG(INFO) << folly::sformat("Mac address is: {}", mac.mac);
}

void KatranSimpleClient::addOrModifyService(const std::string &address,
                                            const std::string &flags, int proto,
                                            bool modify, bool setFlags) {
  LOG(INFO) << folly::sformat("Adding service: {} {}", address, proto);
  auto vip = parseToVip(address, proto);
  const auto &it = vipFlagTranslationTable.find(flags);
  if (it == vipFlagTranslationTable.cend()) {
    LOG(ERROR) << folly::sformat("ERROR: unrecognized flag: {}", flags);
    return;
  }
  VipMeta vipMeta;
  vipMeta.vip = std::move(vip);
  vipMeta.flags = it->second;
  vipMeta.setFlag = setFlags;
  if (modify) {
    if (client_->sync_modifyVip(std::move(vipMeta))) {
      LOG(INFO) << folly::sformat("Vip: {} modified", address);
    } else {
      LOG(ERROR) << "ERROR: Vip not modified";
    }
  } else {
    if (client_->sync_addVip(std::move(vipMeta))) {
      LOG(INFO) << "Vip added";
    } else {
      LOG(ERROR) << "ERROR: Vip not added";
    }
  }
}

void KatranSimpleClient::delService(const std::string &address, int proto) {
  LOG(INFO) << folly::sformat("Deleting service: {} {}", address, proto);
  auto vip = parseToVip(address, proto);
  if (client_->sync_delVip(std::move(vip))) {
    LOG(INFO) << "Vip deleted";
  } else {
    LOG(ERROR) << "ERROR: Vip not deleted";
  }
}

void KatranSimpleClient::updateReal(const std::string &address, uint32_t flags, bool setFlags) {
  LOG(INFO) << folly::sformat("Updating real: {} {}", address, proto);
  RealMeta realMeta;
  realMeta.address = address;
  realMeta.flags = flags;
  realMeta.setFlags = setFlags;

  if (client_->sync_modifyReal(std::move(realMeta))) {
    LOG(INFO) << "Real updated";
  } else {
    LOG(ERROR) << "ERROR: Real not updated";
  }
}

void KatranSimpleClient::updateServerForVip(const std::string &vipAddr,
                                            int proto,
                                            const std::string &realAddr,
                                            uint64_t weight,
                                            const std::string &flags,
                                            bool del) {
  auto vip = parseToVip(vipAddr, proto);
  const auto& it = realFlagTranslationTable.find(flags);
  if (it == realFlagTranslationTable.cend()) {
    LOG(ERROR) << folly::sformat("ERROR: unrecognized flag: {}", flags);
    return;
  }
  auto real = parseToReal(realAddr, weight, it->second);
  Action action;
  if (del) {
    action = Action::DEL;
  } else {
    action = Action::ADD;
  }
  Reals reals;
  reals.push_back(real);
  if (client_->sync_modifyRealsForVip(action, std::move(reals),
                                      std::move(vip))) {
    LOG(INFO) << folly::sformat("Reals for vip: {} modified", vipAddr);
  } else {
    LOG(INFO) << folly::sformat("Reals for vip: {} not modified", vipAddr);
  }
}

void KatranSimpleClient::modifyQuicMappings(const std::string &mapping,
                                            bool del) {
  Action action;
  if (del) {
    action = Action::DEL;
  } else {
    action = Action::ADD;
  }
  QuicReal quicReal = parseToQuicReal(mapping);
  QuicReals reals;
  reals.push_back(std::move(quicReal));
  if (client_->sync_modifyQuicRealsMapping(action, std::move(reals))) {
    LOG(INFO) << "Modified Quic Mappings";
  } else {
    LOG(ERROR) << "Error encountered while modifying the given Quic mappings";
  }
}

std::vector<::lb::katran::Vip> KatranSimpleClient::getAllVips() {
  std::vector<::lb::katran::Vip> vips;
  client_->sync_getAllVips(vips);
  return vips;
}

hcMap KatranSimpleClient::getAllHcs() {
  hcMap retMap;
  client_->sync_getHealthcheckersDst(retMap);
  return retMap;
}

Reals KatranSimpleClient::getRealsForVip(const Vip &vip) {
  Reals reals;
  client_->sync_getRealsForVip(reals, vip);
  return reals;
}

uint64_t KatranSimpleClient::getFlags(const Vip &vip) {
  return client_->sync_getVipFlags(vip);
}

std::string KatranSimpleClient::parseVipFlags(uint64_t flags) {
  std::string flagsStr = "";
  if ((flags & NO_SPORT) > 0) {
    flagsStr += " NO_SPORT ";
  }
  if ((flags & NO_LRU) > 0) {
    flagsStr += " NO_LRU ";
  }
  if ((flags & QUIC_VIP) > 0) {
    flagsStr += " QUIC_VIP ";
  }
  if ((flags & DPORT_HASH) > 0) {
    flagsStr += " DPORT_HASH ";
  }
  if ((flags & LOCAL_VIP) > 0) {
    flagsStr += " LOCAL_VIP ";
  }
  return flagsStr;
}

std::string KatranSimpleClient::parseRealFlags(uint32_t flags) {
  std::string flagsStr = "";
  if ((flags & LOCAL_REAL) > 0) {
    flagsStr += " LOCAL_REAL ";
  }
  return flagsStr;
}

void KatranSimpleClient::list(const std::string &address, int proto) {
  auto vips = getAllVips();
  LOG(INFO) << folly::sformat("vips len: {}", vips.size());
  for (const auto &vip : vips) {
    listVipAndReals(vip);
  }
}

void KatranSimpleClient::listVipAndReals(const Vip &vip) {
  Reals reals = getRealsForVip(vip);
  std::string proto;
  if (vip.protocol == ::IPPROTO_TCP) {
    proto = "tcp";
  } else {
    proto = "udp";
  }
  LOG(INFO) << folly::sformat("VIP: {:<20} Port: {:06d}, Protocol: {}",
                              vip.address, vip.port, proto);
  uint64_t flags = getFlags(vip);
  LOG(INFO) << folly::sformat("Vip's flags: {}", parseVipFlags(flags));
  for (auto real : reals) {
    LOG(INFO) << folly::sformat("-> {:<20} weight {} flags {}", real.address,
                                real.weight, parseRealFlags(real.flags));
  }
}

void KatranSimpleClient::clearAll() {
  LOG(INFO) << "Deleting Vips";
  auto vips = getAllVips();
  for (auto &vip : vips) {
    if (client_->sync_delVip(vip)) {
      LOG(INFO) << "All vips deleted";
    } else {
      LOG(ERROR) << "Error encountered while deleting all vips";
    }
  }
  LOG(INFO) << "Deleting HealthChecks";
  hcMap hcs = getAllHcs();
  for (auto &it : hcs) {
    uint32_t somark = it.first;
    if (client_->sync_delHealthcheckerDst(somark)) {
      LOG(INFO) << folly::sformat("Delelted hc w/ somark: {}", somark);
    } else {
      LOG(ERROR) << folly::sformat("error while deleting hc w/ somark: {}",
                                   somark);
    }
  }
}

void KatranSimpleClient::listQm() {
  LOG(INFO) << "printing address to quic's connection id mapping";
  QuicReals qreals;
  client_->sync_getQuicRealsMapping(qreals);
  for (const auto &qr : qreals) {
    LOG(INFO) << folly::sformat("real: {} = connection id: {}", qr.address,
                                qr.id);
  }
}

void KatranSimpleClient::addHc(const std::string &address, uint32_t somark) {
  Healthcheck hc;
  hc.address = address;
  hc.somark = somark;
  if (client_->sync_addHealthcheckerDst(std::move(hc))) {
    LOG(INFO) << folly::sformat("added hc w/ somark: {}  and addr {}", somark,
                                address);
  } else {
    LOG(ERROR) << folly::sformat(
        "error while add hc w/ somark: {}  and addr {}", somark, address);
  }
}

void KatranSimpleClient::delHc(uint32_t somark) {
  if (client_->sync_delHealthcheckerDst(somark)) {
    LOG(INFO) << folly::sformat("Deleted hc w/ somark: {}", somark);
  } else {
    LOG(ERROR) << folly::sformat("error while deleting hc w/ somark: {}",
                                 somark);
  }
}

void KatranSimpleClient::listHc() {
  hcMap hcs = getAllHcs();
  for (const auto &it : hcs) {
    LOG(INFO) << folly::sformat("somark: {} address: {}", it.first, it.second);
  }
}

void KatranSimpleClient::showSumStats() {
  uint64_t oldPkts = 0;
  uint64_t oldBytes = 0;
  auto vips = getAllVips();
  LOG(INFO) << folly::sformat("vips len {}", vips.size());
  while (true) {
    uint64_t pkts = 0;
    uint64_t bytes = 0;
    for (const auto &vip : vips) {
      Stats stats;
      client_->sync_getStatsForVip(stats, vip);
      pkts += stats.v1;
      bytes += stats.v2;
    }
    auto diffPkts = pkts - oldPkts;
    auto diffBytes = bytes - oldBytes;
    LOG(INFO) << folly::sformat("summary: {} pkts/sec, {} bytes/sec", diffPkts,
                                diffBytes);
    oldPkts = pkts;
    oldBytes = bytes;
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }
}

void KatranSimpleClient::showIcmpStats() {
  int64_t oldIcmpV4 = 0;
  int64_t oldIcmpV6 = 0;
  while (true) {
    Stats stats;
    client_->sync_getIcmpTooBigStats(stats);
    auto IcmpV4 = stats.v1 - oldIcmpV4;
    auto IcmpV6 = stats.v2 - oldIcmpV6;
    LOG(INFO) << folly::sformat(
        "ICMP \"packet too big\": v4 {} pkts/sec, v6 {} pkts/sec", IcmpV4,
        IcmpV6);
    oldIcmpV4 = IcmpV4;
    oldIcmpV6 = IcmpV6;
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }
}

void KatranSimpleClient::showLruStats() {
  uint64_t oldTotalPkts = 0;
  uint64_t oldMiss = 0;
  uint64_t oldTcpMiss = 0;
  uint64_t oldTcpNonSynMiss = 0;
  uint64_t oldFallbackLru = 0;
  while (true) {
    float lruMiss = 0;
    float tcpMiss = 0;
    float tcpNonSynMiss = 0;
    float udpMiss = 0;
    float lruHit = 0;
    Stats stats;
    client_->sync_getLruStats(stats);
    Stats missStats;
    client_->sync_getLruMissStats(missStats);
    Stats fallbackStats;
    client_->sync_getLruFallbackStats(fallbackStats);

    uint64_t diffTotal = stats.v1 - oldTotalPkts;
    uint64_t diffMiss = stats.v2 - oldMiss;
    uint64_t diffTcpMiss = missStats.v1 - oldTcpMiss;
    uint64_t diffTcpNonSynMiss = missStats.v2 - oldTcpNonSynMiss;
    uint64_t diffFallbackLru = fallbackStats.v1 - oldFallbackLru;
    if (diffTotal != 0) {
      lruMiss = float(diffMiss) / float(diffTotal);
      tcpMiss = float(diffTcpMiss) / float(diffTotal);
      tcpNonSynMiss = float(diffTcpNonSynMiss) / float(diffTotal);
      udpMiss = 1 - (tcpMiss + tcpNonSynMiss);
      lruHit = 1 - lruMiss;
    }
    LOG(INFO) << folly::sformat(
        "summary: {:08d} pkts/sec. lru hit: {:.2f}, lru miss: {:.2f}",
        diffTotal, lruHit * 100, lruMiss * 100);
    LOG(INFO) << folly::sformat(
        "(tcp syn: {:.2f}, tcp non-syn: {:.2f},  udp: {:.2f})", tcpMiss,
        tcpNonSynMiss, udpMiss);
    LOG(INFO) << folly::sformat(" fallback lru hit: {:08d} pkts/sec",
                                diffFallbackLru);

    oldTotalPkts = stats.v1;
    oldMiss = stats.v2;
    oldTcpMiss = missStats.v1;
    oldTcpNonSynMiss = missStats.v2;
    oldFallbackLru = fallbackStats.v1;
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }
}

void KatranSimpleClient::showPerVipStats() {
  auto vips = getAllVips();
  std::map<std::string, uint64_t> statsMap;
  // initialize per vip keys
  for (const auto &vip : vips) {
    Stats stats;
    client_->sync_getStatsForVip(stats, vip);
    auto pktKey = folly::to<std::string>(vip.address, ":", vip.port, ":",
                                         vip.protocol, ":pkts");
    auto bytesKey = folly::to<std::string>(vip.address, ":", vip.port, ":",
                                           vip.protocol, ":bytes");
    statsMap[pktKey] = 0;
    statsMap[bytesKey] = 0;
  }
  while (true) {
    for (const auto &vip : vips) {
      auto pktKey = folly::to<std::string>(vip.address, ":", vip.port, ":",
                                           vip.protocol, ":pkts");
      auto bytesKey = folly::to<std::string>(vip.address, ":", vip.port, ":",
                                             vip.protocol, ":bytes");
      Stats stats;
      client_->sync_getStatsForVip(stats, vip);

      auto diffPkts = stats.v1 - statsMap[pktKey];
      auto diffBytes = stats.v2 - statsMap[bytesKey];
      LOG(INFO) << folly::sformat(
          "vip: {:<20} {:08d} pkts/sec, {:08d} bytes/sec", vip.address,
          diffPkts, diffBytes);
      statsMap[pktKey] = stats.v1;
      statsMap[bytesKey] = stats.v2;
    }
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }
}

Vip KatranSimpleClient::parseToVip(const std::string &address,
                                   uint32_t protocol) {
  Vip vip;
  // v6 address, format: [<addr>]:<port>
  std::string host;
  std::string port;
  if (address.find("[") != std::string::npos) {
    std::string regex("\\[(.*?)\\]:(.*)");
    if (!RE2::FullMatch(address, regex, &host, &port)) {
      LOG(ERROR) << folly::sformat("ERROR: invalid v6 address: {}", address);
    }
  } else {
    // v4 address. format <addr>:<port>
    std::vector<std::string> pair;
    folly::split(":", address, pair);
    CHECK_EQ(pair.size(), 2)
        << "Invalid ipv4 format. Expected format is <addr>:<port>";
    host = pair[0];
    port = pair[1];
  }
  auto parsedIPAddr = folly::IPAddress::tryFromString(host);
  if (!parsedIPAddr.hasValue()) {
    LOG(ERROR) << folly::sformat("ERROR: Invalid IP address provided: {}",
                                 host);
  }
  vip.protocol = protocol;
  vip.address = host;
  vip.port = folly::to<int>(port);
  return vip;
}

Real KatranSimpleClient::parseToReal(const std::string &address,
                                     uint32_t weight, uint32_t flags) {
  Real real;
  real.address = address;
  real.weight = weight;
  real.flags = flags;
  return real;
}

QuicReal KatranSimpleClient::parseToQuicReal(const std::string &mapping) {
  std::vector<std::string> mappings;
  folly::split("=", mapping, mappings);
  if (mappings.size() != 2) {
    LOG(ERROR) << "ERROR: quic mapping must be in <addr>=<id> format";
  }
  QuicReal real;
  real.address = mappings[0];
  real.id = folly::to<uint32_t>(mappings[1]);
  return real;
}

std::unique_ptr<KatranServiceAsyncClient>
KatranSimpleClient::createKatranClient(const folly::SocketAddress &addr) {
  AsyncSocket::UniquePtr sock(new AsyncSocket(&evb_, addr));
  sock->setZeroCopy(true);
  auto channel = HeaderClientChannel::newChannel(std::move(sock));
  return std::make_unique<KatranServiceAsyncClient>(std::move(channel));
}

} // namespace katran
} // namespace lb
