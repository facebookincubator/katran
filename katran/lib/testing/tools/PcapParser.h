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
#include <folly/io/IOBuf.h>

#include "katran/lib/PcapStructs.h"

namespace katran {

/**
 * helper class to parse/read/write pcap files and/or packets.
 */
class PcapParser {
 public:
  /**
   * @param string inputFile optional input pcap file to read pckts from
   * @param string outputFile optional output file where pckts would be
   * writen in pcap format.
   */
  explicit PcapParser(
      const std::string& inputFile = "",
      const std::string& outputFile = "");
  ~PcapParser();

  /**
   * @return unique_ptr<IOBuf> ptr to a packet from pcap.
   *
   * helper function which reads one packet in a time from inputFile and returns
   * IOBuf which contains it. if there is no more packets left in a file
   * nullptr will be returned.
   */
  std::unique_ptr<folly::IOBuf> getPacketFromPcap();

  /**
   * @return string packet from pcap file encoded in base64 format
   *
   * helper function which reads one packet in a time from inputFile and returns
   * it in base64 encoding. if there is no more packets left in a file
   * empty string will be returned.
   * Intended use case is to get base64 packet representation which could later
   * be used to build test's fixtures.
   */
  std::string getPacketFromPcapBase64();

  /**
   * @param unique_ptr<IOBuf> ptr to pckt
   * @return string pckt encoded in base64 format
   *
   * helper function which convert provided packet to it's base64 representation
   * for IOBuf copy() could be used to create a new IOBuf ptr to the same
   * mem (as we dont modify it)
   */
  static std::string convertPacketToBase64(std::unique_ptr<folly::IOBuf> pckt);

  /**
   * @param string base64 encoded packet
   * @return unique_ptr<IOBuf> ptr to a packet
   *
   * helper function to get a packet from it's base64 representation.
   */
  static std::unique_ptr<folly::IOBuf> getPacketFromBase64(
      const std::string& encodedPacket);

  /**
   * @param uniqut_ptr<IOBuf> pointer to packet
   * @return bool true on successfull write
   *
   * helper function to write a packet to outputFile in pcap format
   */
  bool writePacket(std::unique_ptr<folly::IOBuf> pckt);

 private:
  /**
   * flag which indicates that this is a first read from pcap file
   * (so we would need to read generic pcap header first)
   */
  bool firstRead_{true};

  /**
   * flag which indicates that this is a first write to pcap file (so we would
   * need to write generic pcap header first).
   */
  bool firstWrite_{true};

  /**
   * names of input and output pcap files (if specified)
   */
  std::string inputFileName_;
  std::string outputFileName_;

  /**
   * file objects for pcap files
   */
  folly::File inputFile_;
  folly::File outputFile_;

  /**
   * maximum packet's size declared in generic pcap header. used for sanity
   * checking.
   */
  uint32_t snaplen_{0};
};

} // namespace katran
