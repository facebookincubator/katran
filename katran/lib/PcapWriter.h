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
#include <vector>

#include <folly/MPMCQueue.h>

#include "katran/lib/DataWriter.h"
#include "katran/lib/PcapMsgMeta.h"

struct PcapWriterStats {
  uint32_t limit{0};
  uint32_t amount{0};
  uint32_t bufferFull{0};
};

namespace katran {

/**
 * helper class wich implements a pcap writer. it writes packets to a file or
 * buffer in pcap format. so they could be read with a existing tools, like
 * wireshark or tcpdump.
 */
class PcapWriter {
 public:
  /**
   * @param shared_ptr<DataWriter> dataWriter ptr to writer implementation
   * @param uint32_t packetLimit max number of packet that can be written.
   * Set to 0 to make it unlimitted.
   * @param uint32_t snaplen is a number of bytes that will be captured
   *
   * couple of notes: for FileWritter if file with filename already
   * exists - the content of this file would be overwritten
   */
  explicit PcapWriter(
      std::shared_ptr<DataWriter> dataWriter,
      uint32_t packetLimit,
      uint32_t snaplen);

  /**
   * @param vector<shared_ptr<DataWriter>> dataWriters vector of per event
   * writers
   * @param uint32_t packetLimit max number of packet that can be written.
   * Set to 0 to make it unlimitted.
   * @param uint32_t snaplen is a number of bytes that will be captured
   *
   */
  PcapWriter(
      std::vector<std::shared_ptr<DataWriter>>& dataWriters,
      uint32_t packetLimit,
      uint32_t snaplen);

  /**
   * @param shared_ptr<MPMCQueue<PcapMsg>> queue where we receive msg to write
   *
   * helper function which starts PcapWriter. it reads from MPMCQueue in a loop
   * and calls writePacket on each received message from the queue untill we
   * receive "marker" message (message with nullptr instead of pointer to IOBuf)
   * which stops the iteratation.
   */
  void run(std::shared_ptr<folly::MPMCQueue<PcapMsg>> queue);

  /**
   * @param shared_ptr<MPMCQueue<PcapMsgMeta>> queue where we receive msg w/
   * metadata to write
   *
   * helper function which starts PcapWriter. it reads from MPMCQueue in a loop.
   * depends on metada it tries to find specific writer for that event and calls
   * writePacket of that writer
   */
  void runMulti(std::shared_ptr<folly::MPMCQueue<PcapMsgMeta>> queue);

  /**
   * @param shared_ptr<MPMCQueue<PcapMsgMeta>> queue where we receive msg from
   *
   * helper function which starts PcapWriter in multiWriter form.
   * it reads from MPMCQueue in a loop and depends on metadata in the message,
   * calls writePacket w/ specific for such event writer
   * on each received message from the queue untill we
   * receive "marker" message (message with nullptr instead of pointer to IOBuf)
   * which stops the iteratation.
   */
  void runMulti(std::shared_ptr<folly::MPMCQueue<PcapMsg>> queue);

  /**
   * Get number of captured packets
   */
  uint32_t packetsCaptured() const {
    return packetAmount_;
  }

  /**
   * return PcapWriter related statistics
   */
  PcapWriterStats getStats();

 private:
  /**
   * @param PcapMsg msg which contains packet to writer
   * @param uint32_t writerId id which is going to be used to write this msg
   *
   * wrapper which implements all the writin logic
   */
  void writePacket(const PcapMsg& msg, uint32_t writerId);

  /**
   * helper function to write pcap header
   */
  bool writePcapHeader(uint32_t writerId);

  /**
   * helper which restart writers
   */
  void restartWriters(uint32_t packetLimit);

  /**
   * helper which stops writers
   */
  void stopWriters();

  /**
   * vector of event to writers mapping. evnet id - position in the vector
   */
  std::vector<std::shared_ptr<DataWriter>> dataWriters_;

  /**
   * internal table, which marks if pcap header was already written by specific
   * writer at corresponding index in dataWriters_
   */
  std::vector<bool> headerExists_;

  /**
   * Amount of packets that have been written in PcapWriter.
   */
  uint32_t packetAmount_{0};

  /**
   * Max number of packets that can be written in a single batch
   */
  uint32_t packetLimit_{0};

  /**
   * Number of bufferFull events: when writer does not have enough
   * space to write packet
   */
  uint32_t bufferFull_{0};

  /**
   * Max number of bytes to be stored.
   */
  const uint32_t snaplen_{0};

  /**
   * lock which protects counters, such as packetAmount_ and packetLimit_
   */
  std::mutex cntrLock_;
};

} // namespace katran
