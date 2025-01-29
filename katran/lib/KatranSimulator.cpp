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

#include "katran/lib/KatranSimulator.h"

#include <folly/IPAddress.h>
#include <glog/logging.h>
#include <cstring>

#include "katran/lib/BpfAdapter.h"

extern "C" {
#include <arpa/inet.h>
#include <linux/ipv6.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
}

namespace katran {

namespace {
constexpr uint16_t kMaxXdpPcktSize = 4096;
constexpr uint16_t kTestPacketSize = 512;
constexpr int kTestRepeatCount = 1;
constexpr uint8_t kDefaultTtl = 64;
constexpr uint8_t kIPv6AddrSize = 16;
constexpr folly::StringPiece kEmptyString = "";
} // namespace

namespace {

void createV4Packet(
    const folly::IPAddress& src,
    const folly::IPAddress& dst,
    std::unique_ptr<folly::IOBuf>& buf,
    uint8_t proto,
    uint16_t size) {
  auto ehdr = reinterpret_cast<struct ethhdr*>(buf->writableData());
  auto iph = reinterpret_cast<struct iphdr*>(
      buf->writableData() + sizeof(struct ethhdr));
  ehdr->h_proto = htons(ETH_P_IP);
  iph->ihl = 5;
  iph->version = 4;
  iph->frag_off = 0;
  iph->protocol = proto;
  iph->check = 0;
  iph->tos = 0;
  iph->tot_len = htons(size);
  iph->daddr = dst.asV4().toLong();
  iph->saddr = src.asV4().toLong();
  iph->ttl = kDefaultTtl;
}

void createV6Packet(
    const folly::IPAddress& src,
    const folly::IPAddress& dst,
    std::unique_ptr<folly::IOBuf>& buf,
    uint8_t proto,
    uint16_t size) {
  auto ehdr = reinterpret_cast<struct ethhdr*>(buf->writableData());
  auto ip6h = reinterpret_cast<struct ipv6hdr*>(
      buf->writableData() + sizeof(struct ethhdr));
  ehdr->h_proto = htons(ETH_P_IPV6);
  ip6h->version = 6;
  ip6h->priority = 0;
  std::memset(ip6h->flow_lbl, 0, sizeof(ip6h->flow_lbl));
  ip6h->nexthdr = proto;
  ip6h->payload_len = htons(size - sizeof(struct ipv6hdr));
  ip6h->hop_limit = kDefaultTtl;
  std::memcpy(
      ip6h->daddr.s6_addr16, dst.asV6().toBinary().data(), kIPv6AddrSize);
  std::memcpy(
      ip6h->saddr.s6_addr16, src.asV6().toBinary().data(), kIPv6AddrSize);
}

void createTcpHeader(
    std::unique_ptr<folly::IOBuf>& buf,
    uint16_t srcPort,
    uint16_t dstPort,
    uint16_t offset) {
  auto tcph = reinterpret_cast<struct tcphdr*>(buf->writableData() + offset);
  std::memset(tcph, 0, sizeof(struct tcphdr));
  tcph->source = htons(srcPort);
  tcph->dest = htons(dstPort);
  tcph->syn = 1;
}

void createUdpHeader(
    std::unique_ptr<folly::IOBuf>& buf,
    uint16_t srcPort,
    uint16_t dstPort,
    uint16_t offset,
    uint16_t size) {
  auto udph = reinterpret_cast<struct udphdr*>(buf->writableData() + offset);
  std::memset(udph, 0, sizeof(struct udphdr));
  udph->source = htons(srcPort);
  udph->dest = htons(dstPort);
  udph->len = size;
}

const std::string toV4String(uint32_t addr) {
  return folly::IPAddressV4::fromLong(addr).str();
}

const std::string toV6String(uint8_t const* v6) {
  folly::ByteRange bytes(v6, kIPv6AddrSize);
  return folly::IPAddressV6::fromBinary(bytes).str();
}

std::string getPcktDst(std::unique_ptr<folly::IOBuf>& pckt) {
  if (pckt->computeChainDataLength() < sizeof(struct ethhdr)) {
    LOG(ERROR) << "resulting packet is invalid";
    return kEmptyString.data();
  }
  const struct ethhdr* ehdr =
      reinterpret_cast<const struct ethhdr*>(pckt->data());
  if (ehdr->h_proto == htons(ETH_P_IP)) {
    if (pckt->computeChainDataLength() <
        (sizeof(struct ethhdr) + sizeof(struct iphdr))) {
      LOG(ERROR) << "resulting ipv4 packet is invalid";
      return kEmptyString.data();
    }
    const struct iphdr* iph = reinterpret_cast<const struct iphdr*>(
        pckt->data() + sizeof(struct ethhdr));
    return toV4String(iph->daddr);
  } else {
    if (pckt->computeChainDataLength() <
        (sizeof(struct ethhdr) + sizeof(struct ipv6hdr))) {
      LOG(ERROR) << "resulting ipv6 packet is invalid";
      return kEmptyString.data();
    }
    const struct ipv6hdr* ip6h = reinterpret_cast<const struct ipv6hdr*>(
        pckt->data() + sizeof(struct ethhdr));
    return toV6String(ip6h->daddr.s6_addr);
  }
}

std::unique_ptr<folly::IOBuf> createPacketFromFlow(const KatranFlow& flow) {
  int offset = sizeof(struct ethhdr);
  bool is_tcp = true;
  bool is_v4 = true;
  size_t l3hdr_len;

  auto srcExp = folly::IPAddress::tryFromString(flow.src);
  auto dstExp = folly::IPAddress::tryFromString(flow.dst);
  if (srcExp.hasError() || dstExp.hasError()) {
    LOG(ERROR) << "malformed src or dst ip address. src: " << flow.src
               << " dst: " << flow.dst;
    return nullptr;
  }
  auto src = srcExp.value();
  auto dst = dstExp.value();
  if (src.family() != dst.family()) {
    LOG(ERROR) << "src and dst must have same address family";
    return nullptr;
  }
  auto pckt = folly::IOBuf::create(kTestPacketSize);
  if (!pckt) {
    LOG(ERROR) << "cannot allocate IOBuf";
    return pckt;
  }
  if (src.family() == AF_INET) {
    l3hdr_len = sizeof(struct iphdr);
  } else {
    is_v4 = false;
    l3hdr_len = sizeof(struct ipv6hdr);
  }
  offset += l3hdr_len;
  switch (flow.proto) {
    case IPPROTO_TCP:
      break;
    case IPPROTO_UDP:
      is_tcp = false;
      break;
    default:
      LOG(ERROR) << "unsupported protocol: " << flow.proto
                 << " must be either TCP or UDP";
      return nullptr;
  }
  pckt->append(kTestPacketSize);
  auto payload_size = kTestPacketSize - sizeof(struct ethhdr);
  if (is_v4) {
    createV4Packet(src, dst, pckt, flow.proto, payload_size);
  } else {
    createV6Packet(src, dst, pckt, flow.proto, payload_size);
  }
  payload_size -= l3hdr_len;
  if (is_tcp) {
    createTcpHeader(pckt, flow.srcPort, flow.dstPort, offset);
  } else {
    createUdpHeader(pckt, flow.srcPort, flow.dstPort, offset, payload_size);
  }
  return pckt;
}

} // namespace

KatranSimulator::KatranSimulator(int progFd) : progFd_(progFd) {
  affinitizeSimulatorThread();
}

KatranSimulator::~KatranSimulator() {}

std::unique_ptr<folly::IOBuf> KatranSimulator::runSimulation(
    std::unique_ptr<folly::IOBuf> pckt) {
  std::unique_ptr<folly::IOBuf> result;
  simulatorEvb_.getEventBase()->runInEventBaseThreadAndWait(
      [&]() { result = runSimulationInternal(std::move(pckt)); });
  return result;
}

std::unique_ptr<folly::IOBuf> KatranSimulator::runSimulationInternal(
    std::unique_ptr<folly::IOBuf> pckt) {
  CHECK(simulatorEvb_.getEventBase()->isInEventBaseThread());
  if (!pckt) {
    LOG(ERROR) << "packet is empty";
    return nullptr;
  }
  if (pckt->isChained()) {
    LOG(ERROR) << "Chained buffers are not supported";
    return nullptr;
  }
  if (pckt->length() > kMaxXdpPcktSize) {
    LOG(ERROR) << "packet is too big";
    return nullptr;
  }
  auto rpckt = folly::IOBuf::create(kMaxXdpPcktSize);
  if (!rpckt) {
    LOG(ERROR) << "not able to allocate memory for resulting packet";
    return rpckt;
  }
  uint32_t output_pckt_size{0};
  uint32_t prog_ret_val{0};
  auto res = BpfAdapter::testXdpProg(
      progFd_,
      kTestRepeatCount,
      pckt->writableData(),
      pckt->length(),
      rpckt->writableData(),
      &output_pckt_size,
      &prog_ret_val);
  if (res < 0) {
    LOG(ERROR) << "failed to run simulator";
    return nullptr;
  }
  if (prog_ret_val != XDP_TX) {
    return nullptr;
  }
  rpckt->append(output_pckt_size);
  return rpckt;
}

const std::string KatranSimulator::getRealForFlow(const KatranFlow& flow) {
  auto pckt = createPacketFromFlow(flow);
  if (!pckt) {
    return kEmptyString.data();
  }
  auto rpckt = runSimulation(std::move(pckt));
  if (!rpckt) {
    return kEmptyString.data();
  }
  return getPcktDst(rpckt);
}

void KatranSimulator::affinitizeSimulatorThread() {
  simulatorEvb_.getEventBase()->runInEventBaseThreadAndWait([]() {
    cpu_set_t cpuSet;
    CPU_ZERO(&cpuSet);
    CPU_SET(0, &cpuSet);
    pthread_t currentThread = pthread_self();
    auto ret =
        pthread_setaffinity_np(currentThread, sizeof(cpu_set_t), &cpuSet);
    if (ret != 0) {
      LOG(ERROR) << "Error while affinitizing simulator thread to CPU 0: "
                 << ret;
    }
  });
}

} // namespace katran
