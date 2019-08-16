#pragma once

#include <folly/io/IOBuf.h>
#include <memory>
#include <string>

namespace katran {

/**
 * KatranFlow structs contains all the fields, which
 * are unique (from katran's point of view) for each flow
 */
struct KatranFlow {
  // source ip address of the packet
  std::string src;
  // destination ip address of the packet
  std::string dst;
  uint16_t srcPort;
  uint16_t dstPort;
  // protocol number (e.g. 6 for TCP, 17 for UDP)
  uint8_t proto;
};

/**
 * KatranSimulator allow end user to simulate what is going to happen
 * with specified packet after it is going to be processed by katran
 * load balancer. e.g. where (address of the real) this packet is going
 * to be sent
 */
class KatranSimulator final {
public:
  KatranSimulator() = delete;
  /**
   * @param int progFd descriptor of katran xdp program
   */
  explicit KatranSimulator(int progFd);
  ~KatranSimulator();

  /**
   * @param KatranFlow& flow which we are intersting in
   * @return string ip address of the real (or empty string if packet wont be
   * sent)
   *
   * getRealForFlow helps to answer the question (by returning ip address of the
   * real) "where specific flow is going to be sent"
   */
  const std::string getRealForFlow(const KatranFlow &flow);

private:
  // runSimulation takes packet (in iobuf represenation) and
  // run it through katran bpf program. it returns modified pckt, if result
  // was XDP_TX or nullptr otherwise.
  std::unique_ptr<folly::IOBuf>
  runSimulation(std::unique_ptr<folly::IOBuf> &pckt);
  int progFd_;
};
} // namespace katran
