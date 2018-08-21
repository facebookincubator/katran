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

#include <folly/File.h>
#include <folly/MPMCQueue.h>

#include "PcapMsg.h"

namespace xdpdump {

/**
 * helper class wich implements a pcap writer. it writes packets to a file
 * in pcap format. so they could be read with a existing tools, like
 * wireshark or tcpdump.
 */
class PcapWriter {
public:
  /**
   * DataWriter is used to abstract writing to file and ByteRange from
   * the logic of PcapWriter.
   */
  class DataWriter {
  public:
    virtual ~DataWriter() {}

    /**
     * Called to WriteData
     */
    virtual void writeData(const void *ptr, size_t size) = 0;

    /**
     * @param amount -- amount of bytes to write.
     *
     * Check if we're able to write `amount` bytes into storage. Returns true
     * if yes.
     */
    virtual bool available(size_t amount) = 0;

    size_t writtenBytes() { return writtenBytes_; }

  protected:
    /**
     * size_t wryteBytes is used to record amount of bytes that already
     * have been written.
     */
    size_t writtenBytes_{0};
  };

  /**
   * FileWriter is used to write pcap-data into file.
   */
  class FileWriter : public DataWriter {
  public:
    explicit FileWriter(const std::string &filename);

    void writeData(const void *ptr, size_t size) override;

    bool available(size_t amount) override;

  private:
    folly::File pcapFile_;
  };

  /**
   * ByteRangeWriter is used to write pcap-data into MutableByteRange.
   */
  class ByteRangeWriter : public DataWriter {
  public:
    explicit ByteRangeWriter(folly::MutableByteRange &buffer);

    void writeData(const void *ptr, size_t size) override;

    bool available(size_t amount) override;

  private:
    folly::MutableByteRange &buffer_;
  };

  /**
   * @param string filename path to the file, where we want to write
   * @param uint32_t packetLimit max number of packet that can be written.
   * Set to 0 to make it unlimitted.
   * @param uint32_t snaplen is a number of bytes that will be captured
   *
   *
   * couple of notes: if file with filename already exists - the content of this
   * file would be overwritten
   */
  explicit PcapWriter(std::shared_ptr<DataWriter> dataWriter,
                      uint32_t packetLimit, uint32_t snaplen);

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
   * Get number of captured packets
   */
  uint32_t packetsCaptured() const { return packetAmount_; }

private:
  /**
   * @param PcapMsg msg which contains packet to writer
   *
   * wrapper which implements all the writing to the file logic
   */
  void writePacket(const PcapMsg &msg);

  /**
   * DataWriter is used to write data into either file or byte range
   */
  std::shared_ptr<DataWriter> dataWriter_;

  /**
   * Amount of packets that have been written in PcapWriter.
   */
  uint32_t packetAmount_{0};

  /**
   * Max number of packets that can be written.
   */
  const uint32_t packetLimit_{0};

  /**
   * Max number of bytes to be stored.
   */
  const uint32_t snaplen_{0};
};

} // namespace xdpdump
