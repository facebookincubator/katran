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

#include "XdpDump.h"

#include <arpa/inet.h>
#include <chrono>
#include <iostream>
#include <signal.h>

#include <bcc/libbpf.h>
#include <bcc/table_storage.h>
#include <folly/Format.h>
#include <folly/io/async/EventBaseManager.h>
#include <glog/logging.h>

#include "PcapWriter.h"
#include "XdpDumpKern.h"

namespace xdpdump {

namespace {

const std::string kBpfFunc = "xdpdump";
const std::string kPcapFunc = "process";
const std::string kRootJmpArray = "jmp";
const std::string kPerfEventMap = "perf_event_map";
const std::string kXdpMode = "xdp";
constexpr int kBpfLogBufSize = 1024 * 1024 * 1;
constexpr int kIoPoolSize = 1;
int kMapPos = 0;
constexpr unsigned kNoFlags = 0;
constexpr uint32_t kNoSample = 1;
constexpr uint32_t kQueueCapacity = 2048;

uint64_t getPossibleCpus() {
  static const char *fcpu = "/sys/devices/system/cpu/possible";
  unsigned int start, end, possible_cpus = 0;
  char buff[128];
  FILE *fp;

  fp = fopen(fcpu, "r");
  if (!fp) {
    printf("Failed to open %s: '%s'!\n", fcpu, strerror(errno));
    exit(1);
  }

  while (fgets(buff, sizeof(buff), fp)) {
    if (sscanf(buff, "%u-%u", &start, &end) == 2) {
      possible_cpus = start == 0 ? end + 1 : 0;
      break;
    }
  }

  fclose(fp);
  if (!possible_cpus) {
    printf("Failed to retrieve # possible CPUs!\n");
    exit(1);
  }

  return possible_cpus;
}

} // namespace

XdpDump::XdpDump(folly::EventBase *eventBase, XdpDumpFilter filter,
                 std::shared_ptr<PcapWriter> pcapWriter)
    : folly::AsyncTimeout(eventBase, AsyncTimeout::InternalEnum::INTERNAL),
      filter_(filter), pcapWriter_(pcapWriter), eventBase_(eventBase) {}

XdpDump::~XdpDump() {}

void XdpDump::prepareSharedMap() {
  VLOG(2) << "preparing shared env: map path " << filter_.map_path
          << " map pos: " << kMapPos;

  auto ts = ebpf::createSharedTableStorage();
  ts->Delete({kRootJmpArray});

  ebpf::TableDesc desc;
  desc.type = BPF_MAP_TYPE_PROG_ARRAY;
  desc.name = kRootJmpArray;
  desc.fd = ebpf::FileDesc(::dup(jmpFd_));
  ts->Insert({kRootJmpArray}, std::move(desc));
}

void XdpDump::compile() {
  VLOG(2) << "compiling bpf prog";
  std::vector<const char *> cflags;
  for (const auto &flag : cflags_) {
    LOG(INFO) << "adding compile flag: " << flag;
    cflags.push_back(flag.c_str());
  }
  try {
    funcName_ = kBpfFunc;
    VLOG(2) << "compiling xdpdump from string";
    bpf_ = std::make_unique<ebpf::BPFModule>(kNoFlags);
    bpf_->load_string(kXdpDumpProg, cflags.data(), cflags.size());
  } catch (const std::runtime_error &e) {
    LOG(ERROR) << "Error while load xdpdump prog";
    throw e;
  }
}

void XdpDump::prepareCflags() {
  if (filter_.ipv6) {
    if ((filter_.flags & kSrcSet) > 0) {
      cflags_.push_back(folly::sformat("-DSRCV6_0={}", filter_.srcv6[0]));
      cflags_.push_back(folly::sformat("-DSRCV6_1={}", filter_.srcv6[1]));
      cflags_.push_back(folly::sformat("-DSRCV6_2={}", filter_.srcv6[2]));
      cflags_.push_back(folly::sformat("-DSRCV6_3={}", filter_.srcv6[3]));
    }
    if ((filter_.flags & kDstSet) > 0) {
      cflags_.push_back(folly::sformat("-DDSTV6_0={}", filter_.dstv6[0]));
      cflags_.push_back(folly::sformat("-DDSTV6_1={}", filter_.dstv6[1]));
      cflags_.push_back(folly::sformat("-DDSTV6_2={}", filter_.dstv6[2]));
      cflags_.push_back(folly::sformat("-DDSTV6_3={}", filter_.dstv6[3]));
    }
  } else {
    if ((filter_.flags & kSrcSet) > 0) {
      cflags_.push_back(folly::sformat("-DSRCV4={}", filter_.src));
    }
    if ((filter_.flags & kDstSet) > 0) {
      cflags_.push_back(folly::sformat("-DDSTV4={}", filter_.dst));
    }
  }
  if ((filter_.flags & kSportSet) > 0) {
    cflags_.push_back(folly::sformat("-DSPORT={}", htons(filter_.sport)));
  }
  if ((filter_.flags & kDportSet) > 0) {
    cflags_.push_back(folly::sformat("-DDPORT={}", htons(filter_.dport)));
  }
  if ((filter_.flags & kProtoSet) > 0) {
    cflags_.push_back(folly::sformat("-DPROTO={}", filter_.proto));
  }
  if (filter_.offset_len > 0) {
    cflags_.push_back(folly::sformat("-DOFFSET={}", filter_.offset));
    cflags_.push_back(folly::sformat("-DO_LEN={}", filter_.offset_len));
    cflags_.push_back(folly::sformat("-DO_PATTERN={}", filter_.pattern));
  }
  if (filter_.count > 0) {
    // not yet used
    cflags_.push_back(folly::sformat("-DCOUNT={}", filter_.count));
  }
  if (filter_.cpu >= 0) {
    cflags_.push_back(folly::sformat("-DCPU_NUMBER={}", filter_.cpu));
  }
}

void XdpDump::load() {
  perfEventMapFd_ = bpf_->table_fd(kPerfEventMap);
  if (perfEventMapFd_ < 0) {
    throw std::runtime_error("cant get fd for perf map");
  }
  auto fnStart = bpf_->function_start(funcName_);
  if (!fnStart) {
    throw std::runtime_error("cant find function w/ name " +
                             folly::to<std::string>(funcName_));
  }

  auto fnSize = bpf_->function_size(funcName_);
  auto bpfLogBuf = std::make_unique<char[]>(kBpfLogBufSize);
  progFd_ = bpf_prog_load(BPF_PROG_TYPE_XDP, funcName_.c_str(),
                          reinterpret_cast<struct bpf_insn *>(fnStart), fnSize,
                          bpf_->license(), bpf_->kern_version(),
                          0 /* log_level */, bpfLogBuf.get(), kBpfLogBufSize);
  if (progFd_ < 0) {
    VLOG(2) << "fd is negative: " << progFd_ << " errno: " << errno
            << " errno str: " << folly::to<std::string>(std::strerror(errno))
            << " fn size: " << fnSize;
    throw std::runtime_error("cant load bpfprog. error:" +
                             folly::to<std::string>(bpfLogBuf.get()));
  } else {
    VLOG(2) << "progs fd is: " << progFd_;
  }
}

void XdpDump::attach() {
  auto bpfError = bpf_update_elem(jmpFd_, &kMapPos, &progFd_, 0);
  if (bpfError) {
    throw std::runtime_error("Error while updating value in map: " +
                             folly::to<std::string>(std::strerror(errno)));
  }
}

void XdpDump::detach() {
  VLOG(2) << "detaching xdpdump from rootlet";
  auto bpfError = bpf_delete_elem(jmpFd_, &kMapPos);
  if (bpfError) {
    throw std::runtime_error("Error while deleting key from map: " +
                             folly::toStdString(folly::errnoStr(errno)));
  }
}

void XdpDump::run() {
  getJmpFd();
  prepareSharedMap();
  prepareCflags();
  compile();
  load();
  pumpEventBase();      // run evbThread_ here
  tryStartPcapWriter(); // create: queue_ -> writerThread_ if pcap
  startEventReaders();
  startSigHandler();
  attach();
  LOG(INFO) << "Starting xdpdump";
  sleepForever();
  LOG(INFO) << "Detaching bpf";
  detach();
  LOG(INFO) << "Finalized xdpdump";
}

void XdpDump::timeoutExpired() noexcept { stop(); }

void XdpDump::getJmpFd() {
  jmpFd_ = bpf_obj_get(filter_.map_path.c_str());
  if (jmpFd_ < 0) {
    throw std::runtime_error(
        "cant get fd of shared map, probably xdp is not supported");
  }
}

void XdpDump::sleepForever() {
  // Wait until XdpDump::stop won't terminate eventBase_
  writerThread_.join();
}

void XdpDump::pumpEventBase() {
  if (!eventBase_->isRunning()) {
    evbThread_ = std::thread([this]() {
      this->eventBase_->loopForever();
      VLOG(3) << "End of evbThread";
    });
  }
}

void XdpDump::tryStartPcapWriter() {
  if (pcapWriter_) {
    queue_ = std::make_shared<folly::MPMCQueue<PcapMsg>>(kQueueCapacity);
    writerThread_ = std::thread([this]() {
      this->eventBase_->waitUntilRunning();
      this->pcapWriter_->run(this->queue_);
      this->eventBase_->terminateLoopSoon();
      this->evbThread_.join();
      VLOG(3) << "End of writerThread";
    });
  } else {
    writerThread_ = std::thread([this]() {
      this->evbThread_.join();
      VLOG(3) << "End of writerThread";
    });
  }
}

void XdpDump::startEventReaders() {
  uint64_t numCpu = getPossibleCpus();
  std::shared_ptr<XdpEventLogger> eventLogger_;
  eventLogger_ = std::make_shared<ProgLogger>(filter_.mute, std::cerr);
  for (int cpu = 0; cpu < numCpu; ++cpu) {
    auto reader = std::make_unique<XdpEventReader>(queue_, eventLogger_,
                                                   filter_.pages, cpu);
    if (!reader->open(perfEventMapFd_, eventBase_, kNoSample)) {
      LOG(ERROR) << "Perf event queue init failed for cpu: " << cpu;
    } else {
      eventReaders_.push_back(std::move(reader));
    }
  }
  if (eventReaders_.size() == 0) {
    throw std::runtime_error("none of eventReaders were initialized");
  }
}

void XdpDump::startSigHandler() {
  sigHandler_ = std::make_unique<XdpDumpSignalHandler>(eventBase_, this);
  sigHandler_->registerSignalHandler(SIGTERM);
  sigHandler_->registerSignalHandler(SIGINT);
}

void XdpDump::clear() {
  VLOG(2) << "removing xdpdump from shared array";
  getJmpFd();
  detach();
}

void XdpDump::stop() {
  if (queue_) {
    VLOG(2) << "stoping pcap writer";
    PcapMsg stopMsg(nullptr, 0, 0);
    queue_->blockingWrite(std::move(stopMsg));
  } else {
    eventBase_->terminateLoopSoon();
  }

  VLOG(2) << "XdpDump is stopped";
}

XdpDump::XdpDumpSignalHandler::XdpDumpSignalHandler(folly::EventBase *evb,
                                                    XdpDump *parent)
    : folly::AsyncSignalHandler(evb) {
  parent_ = parent;
}

void XdpDump::XdpDumpSignalHandler::signalReceived(int signum) noexcept {
  LOG(INFO) << "Signal: " << signum << ", stopping xdpdump";
  parent_->stop();
}

} // namespace xdpdump
