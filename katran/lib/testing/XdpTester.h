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
#include <utility>
#include <vector>

#include "PcapParser.h"
#include "katran/lib/BpfAdapter.h"

namespace katran {

/**
 * structure with config params for XdpTester.
 */
struct TesterConfig {
  /**
   * vector of input test data to run tests from fixtures.
   * first value in pair must be base64 representation of a packet
   * second one is a test's description.
   */
  std::vector<std::pair<std::string, std::string>> outputData;
  /**
   * vector of output (control) data to run tests from fixtures.
   * actual output of bpf prog's run would be compared to control data in this
   * vector.
   * first value in a pair must be base64 representation of a packet
   * second one is a return code of bpf prog in string format (e.g. XDP_PASS,
   * XDP_DROP, XDP_TX; as specified in bpf.h)
   */
  std::vector<std::pair<std::string, std::string>> inputData;
  /**
   * path to output pcap file. could be omitted. if specified - output of
   * testPcktsFromPcap run would be writen to this file
   */
  std::string outputFileName;
  /**
   * path to input pcap file. could be omitted, if tests are going to be done
   * from fixtures.
   */
  std::string inputFileName;
  /**
   * descriptor of bpf's program to test.
   */
  int bpfProgFd{-1};
};

/**
 * class which implements generic tester for xdp bpf program.
 * it could either use pcap file for input data (and optional write result
 * to output file in pcap format as well) or predefined test fixtures.
 */
class XdpTester {
 public:
  explicit XdpTester(const TesterConfig& config);
  /**
   * helper function to print packets to stdout in base64 format from input
   * pcap file. use case: create data for text fixtures.
   */
  void printPcktBase64();

  /**
   * helper function which reads pckts from pcap file, uses em as an input
   * for bpf program and logs a result of the program's run. optionaly
   * (if output file is specified) writes modified (after prog's run) packet
   * to output file.
   */
  void testPcktsFromPcap();

  /**
   * @param const int bpf program fd.
   *
   * helper function to set bpf's program descriptor.
   */
  void setBpfProgFd(const int progFd) {
    config_.bpfProgFd = progFd;
  }

  /**
   * helper function to run tests on data from test fixtures
   * (inpu/outputData vectors from tester's config.)
   */
  void testFromFixture();

  /**
   * @param vector<string, string> new input fixtures
   * @param vector<string, string> new output fixtures
   * helper function which set test fixtures to new values
   */
  void resetTestFixtures(
      const std::vector<std::pair<std::string, std::string>>& inputData,
      const std::vector<std::pair<std::string, std::string>>& outputData);

  /**
   * @param int repeat      how many time should we repeat the test
   * @param int position    of the packet if fixtures vector.
   * helper function to run perf test on specified packet from test fixtures
   * if position is negative - run perf tests on every packet in fixtures
   */
  void testPerfFromFixture(uint32_t repeat, const int position = -1);

  /**
   * @param IOBuf with packet data to write.
   *
   * helper function to write packet in pcap format to specified outputFilenName
   */
  void writePcapOutput(std::unique_ptr<folly::IOBuf>&& buf);

 private:
  TesterConfig config_;
  PcapParser parser_;
  BpfAdapter adapter_;
};

} // namespace katran
