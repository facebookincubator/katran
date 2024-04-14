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

#include "katran/lib/testing/PcapParser.h"

#include <chrono>
#include <stdexcept>

#include <folly/FileUtil.h>
#include <glog/logging.h>

#include "katran/lib/testing/Base64Helpers.h"

namespace katran {

namespace {
constexpr uint32_t kPcapWriterMagic = 0xa1b2c3d4;
constexpr uint16_t kVersionMajor = 2;
constexpr uint16_t kVersionMinor = 4;
constexpr int32_t kGmt = 0;
constexpr uint32_t kAccuracy = 0;
constexpr uint32_t kSnapLen = 65535; // defined in xdpdump prog
constexpr uint32_t kEthernet = 1;
} // namespace

PcapParser::PcapParser(
    const std::string& inputFile,
    const std::string& outputFile)
    : inputFileName_(inputFile), outputFileName_(outputFile) {
  if (!inputFile.empty()) {
    // readonly by default
    try {
      inputFile_ = folly::File(inputFile);
    } catch (const std::exception& e) {
      LOG(ERROR) << "exception while opening file " << inputFile << " : "
                 << e.what();
      throw;
    }
  }

  if (!outputFile.empty()) {
    try {
      outputFile_ = folly::File(outputFile, O_RDWR | O_CREAT | O_TRUNC);
    } catch (const std::exception& e) {
      LOG(INFO) << "exception while opening file " << outputFile << " : "
                << e.what();
      throw;
    }
  }
}

PcapParser::~PcapParser() {
  if (!inputFileName_.empty()) {
    auto res = inputFile_.closeNoThrow();
    if (!res) {
      LOG(INFO) << "error while closing file: " << inputFileName_;
    }
  }
  if (!outputFileName_.empty()) {
    auto res = outputFile_.closeNoThrow();
    if (!res) {
      LOG(INFO) << "error while closing file: " << outputFileName_;
    }
  }
}

std::unique_ptr<folly::IOBuf> PcapParser::getPacketFromPcap() {
  const struct pcaprec_hdr_s* pcaprec_hdr;
  std::string tmpBuf;
  uint32_t pkt_len;
  bool res;
  if (inputFileName_.empty()) {
    LOG(INFO) << "no input filed specified";
    return nullptr;
  }
  auto fd = inputFile_.fd();
  if (firstRead_) {
    firstRead_ = false;
    // read pcap header in the beginning of the file and some sanity checking
    const struct pcap_hdr_s* pcap_hdr;
    res = folly::readFile(fd, tmpBuf, sizeof(struct pcap_hdr_s));
    if (!res || tmpBuf.size() != sizeof(struct pcap_hdr_s)) {
      LOG(ERROR) << "cant read pcap_hdr_s from input file";
      return nullptr;
    }
    pcap_hdr = reinterpret_cast<const struct pcap_hdr_s*>(tmpBuf.c_str());

    VLOG(2) << "pcap hdr:" << "\nversion major: " << pcap_hdr->version_major
            << "\nversion minor: " << pcap_hdr->version_minor
            << "\nmagic number: " << pcap_hdr->magic_number
            << "\nnetwork: " << pcap_hdr->network;

    snaplen_ = pcap_hdr->snaplen;
    VLOG(2) << "snaplen: " << snaplen_;
  }
  // read per record header and some sanity checking.
  res = folly::readFile(fd, tmpBuf, sizeof(struct pcaprec_hdr_s));
  if (!res || tmpBuf.size() != sizeof(struct pcaprec_hdr_s)) {
    LOG(ERROR) << "cant read pcaprec_hdr_s from input file";
    return nullptr;
  }
  pcaprec_hdr = reinterpret_cast<const struct pcaprec_hdr_s*>(tmpBuf.c_str());
  pkt_len = pcaprec_hdr->incl_len;
  VLOG(2) << "pckt len: " << pkt_len;
  if (pkt_len > snaplen_) {
    LOG(INFO) << "error in pcap file. incl_len > snaplen";
    return nullptr;
  }
  // read pckt from pcap file
  res = folly::readFile(fd, tmpBuf, pkt_len);
  if (!res || tmpBuf.size() != pkt_len) {
    LOG(ERROR) << "cant read packet from pcap file";
    return nullptr;
  }
  auto buf = folly::IOBuf::copyBuffer(tmpBuf);
  return buf;
}

std::string PcapParser::getPacketFromPcapBase64() {
  auto buf = getPacketFromPcap();
  if (buf != nullptr) {
    return Base64Helpers::base64Encode(buf.get());
  } else {
    return "";
  }
}

std::string PcapParser::convertPacketToBase64(
    std::unique_ptr<folly::IOBuf> pckt) {
  return Base64Helpers::base64Encode(pckt.get());
}

std::unique_ptr<folly::IOBuf> PcapParser::getPacketFromBase64(
    const std::string& encodedPacket) {
  auto pckt = Base64Helpers::base64Decode(encodedPacket);
  return folly::IOBuf::copyBuffer(pckt);
}

bool PcapParser::writePacket(std::unique_ptr<folly::IOBuf> pckt) {
  uint32_t len = pckt->length();
  auto fd = outputFile_.fd();

  if (firstWrite_) {
    firstWrite_ = false;
    struct pcap_hdr_s hdr {
      .magic_number = kPcapWriterMagic, .version_major = kVersionMajor,
      .version_minor = kVersionMinor, .thiszone = kGmt, .sigfigs = kAccuracy,
      .snaplen = kSnapLen, .network = kEthernet
    };
    auto res = folly::writeFull(fd, &hdr, sizeof(hdr));
    if (!res) {
      LOG(INFO) << "cant write generic pcap header";
      return false;
    }
  }

  auto unix_usec =
      std::chrono::duration_cast<std::chrono::microseconds>(
          std::chrono::high_resolution_clock::now().time_since_epoch())
          .count();
  // 1sec = 1mil usec
  const uint32_t now_sec = unix_usec / 1000000;
  // in pcap format ts_usec is a offset in msec after ts_sec.
  const uint32_t now_usec = unix_usec - now_sec * 1000000;
  pcaprec_hdr_s rec_hdr{
      .ts_sec = now_sec, .ts_usec = now_usec, .incl_len = len, .orig_len = len};

  auto res = folly::writeFull(fd, &rec_hdr, sizeof(rec_hdr));
  if (!res) {
    return false;
  }
  res = folly::writeFull(fd, pckt->data(), len);
  if (!res) {
    return false;
  }
  return true;
}

} // namespace katran
