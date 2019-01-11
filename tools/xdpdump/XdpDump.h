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

#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <bcc/bpf_module.h>
#include <folly/MPMCQueue.h>
#include <folly/io/async/AsyncSignalHandler.h>
#include <folly/io/async/AsyncTimeout.h>
#include <folly/io/async/EventBase.h>

#include "PcapMsg.h"
#include "XdpDumpStructs.h"
#include "XdpEventReader.h"

namespace folly {
class EventBase;
}

namespace xdpdump {

/**
 * flags which show which field is set in filter struct
 */
constexpr uint8_t kSrcSet = (1 << 0);
constexpr uint8_t kDstSet = (1 << 1);
constexpr uint8_t kSportSet = (1 << 2);
constexpr uint8_t kDportSet = (1 << 3);
constexpr uint8_t kProtoSet = (1 << 4);

/**
 * Main class which implements xdpdump util - tcpdump like util to capture
 * packets on "XDP level" (as xdp could either drop or tx this packets - we
 * we wont be able to see em with tcpdump as this packets will never hit
 * kernel's tcp/ip stack).
 */
class XdpDump : public folly::AsyncTimeout {
public:
  /**
   * @param EventBase* eventBase for AsyncTimeout
   * @param XdpDumpFilter filter
   * @param std::shared_ptr<PcapWriter> pcapWriter
   *
   * we pass filter object which contains all the field (such as src/dst/
   * or a line for pcap-based filter) which describes what packets we want to
   * capture
   */
  explicit XdpDump(folly::EventBase *eventBase, XdpDumpFilter filter,
                   std::shared_ptr<PcapWriter> pcapWriter);

  /**
   * Destructor for XdpDump.
   */
  ~XdpDump();

  /**
   * helper function to remove xdpdump from rootlet's root array
   */
  void clear();

  /**
   * helper function which starts xdpdump
   */
  void run();

  /**
   * timeout function
   */
  virtual void timeoutExpired() noexcept override;

private:
  /**
   * helper class which implements sighandler. this allow us to detach
   * xdpdump from rootlets array when user decided to stop the program.
   */
  class XdpDumpSignalHandler : public folly::AsyncSignalHandler {
  public:
    XdpDumpSignalHandler(folly::EventBase *evb, XdpDump *parent);
    ~XdpDumpSignalHandler() override {}

    void signalReceived(int signum) noexcept override;

  private:
    XdpDump *parent_;
  };
  /**
   * helper function which compiles bpf program.
   */
  void compile();

  /**
   * helper function which loads bpf program in kernel
   */
  void load();

  /**
   * helper function which prepares and passing rootlet's prog fd to bpf prog
   */
  void prepareSharedMap();

  /**
   * helper function which retrievs rootlet's jump table fd from pinned map
   */
  void getJmpFd();

  /**
   * helper function to pump eventBase_
   */
  void pumpEventBase();

  /**
   * helper function which start pcap writer if needed
   */
  void tryStartPcapWriter();

  /**
   * helper function which start perf event reader
   */
  void startEventReaders();

  /**
   * helper function which starts signal handler
   */
  void startSigHandler();

  /**
   * helper function which attaches loaded bpf program to rootlet.
   */
  void attach();

  /**
   * helper function which detaches xdpdump from rootlet's array
   */
  void detach();

  /**
   * as we are doing all the work in separate threads we need to block our main
   * one. this function is basicaly blocks main thread "waiting for evb to stop"
   * (which happens only on sigint receiving)
   */
  void sleepForever();

  /**
   * helper function which prepares cflags for bpf prog compilation.
   * cflags are based on info which has been provided inside XdpDumpFilter
   * struct
   */
  void prepareCflags();

  /**
   * helper function which stop both pcapWriter (if running)
   * and detach xdpdump from rootlet
   */
  void stop();

  /**
   * structs which describes in what packets are we interested in
   * as well as contains some metainfo (such as rootlets map location/
   * our position in it/ pcap's file location etc etc etc)
   */
  XdpDumpFilter filter_;

  /**
   * pcapWriter is used to store pcap-data into file or byte range.
   */
  std::shared_ptr<PcapWriter> pcapWriter_{nullptr};

  /**
   * bpf provider which is used to created bpf prog. depends on configuration
   * could be either Bcc or Pcap compiler
   */
  std::unique_ptr<ebpf::BPFModule> bpf_;

  /**
   * evbThread, which run all event readers and sighandler.
   */
  std::thread evbThread_;

  int perfEventMapFd_;
  /**
   * bpf prog fd
   */
  int progFd_;

  /**
   * fd of rootlet's jump array (array of bpf progs)
   */
  int jmpFd_;

  /**
   * vector of eventReaders (there is one event reader per cpu core)
   */
  std::vector<std::unique_ptr<XdpEventReader>> eventReaders_;

  /**
   * vector of cflags, which are passed to bpf backedn during compilation phase
   */
  std::vector<std::string> cflags_;
  std::unique_ptr<XdpDumpSignalHandler> sigHandler_;
  std::thread writerThread_;

  /**
   * MPMCQueue where we pass PcapMsg from perfEventReaders to PcapWriter
   */
  std::shared_ptr<folly::MPMCQueue<PcapMsg>> queue_;

  /**
   * name of main bpf function
   */
  std::string funcName_;

  /**
   * name of main bpf function
   */
  folly::EventBase *eventBase_;
};

} // namespace xdpdump
