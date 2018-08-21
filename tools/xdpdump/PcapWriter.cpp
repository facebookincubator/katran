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

#include "PcapWriter.h"

#include "PcapStructs.h"
#include <chrono>
#include <folly/FileUtil.h>

namespace xdpdump {

namespace {
constexpr uint32_t kPcapWriterMagic = 0xa1b2c3d4;
constexpr uint16_t kVersionMajor = 2;
constexpr uint16_t kVersionMinor = 4;
constexpr int32_t kGmt = 0;
constexpr uint32_t kAccuracy = 0;
constexpr uint32_t kMaxSnapLen = 0xFFFF; // 65535
constexpr uint32_t kEthernet = 1;
} // namespace

PcapWriter::PcapWriter(std::shared_ptr<DataWriter> dataWriter,
                       uint32_t packetLimit, uint32_t snaplen)
    : dataWriter_(dataWriter), packetLimit_(packetLimit), snaplen_(snaplen) {}

void PcapWriter::writePacket(const PcapMsg &msg) {
  auto unix_usec =
      std::chrono::duration_cast<std::chrono::microseconds>(
          std::chrono::high_resolution_clock::now().time_since_epoch())
          .count();
  // 1sec = 1mil usec
  const uint32_t now_sec = unix_usec / 1000000;
  // in pcap format ts_usec is a offset in msec after ts_sec.
  const uint32_t now_usec = unix_usec - now_sec * 1000000;
  pcaprec_hdr_s rec_hdr{
      .ts_sec = now_sec,
      .ts_usec = now_usec,
  };

  rec_hdr.incl_len = msg.getCapturedLen();
  rec_hdr.orig_len = msg.getOrigLen();
  dataWriter_->writeData(&rec_hdr, sizeof(rec_hdr));
  dataWriter_->writeData(msg.getRawBuffer(), msg.getCapturedLen());
}

void PcapWriter::run(std::shared_ptr<folly::MPMCQueue<PcapMsg>> queue) {

  if (!dataWriter_->available(sizeof(pcap_hdr_s))) {
    LOG(ERROR) << "DataWriter failed to write a header. Too few space.";
    return;
  }

  pcap_hdr_s hdr{.magic_number = kPcapWriterMagic,
                 .version_major = kVersionMajor,
                 .version_minor = kVersionMinor,
                 .thiszone = kGmt,
                 .sigfigs = kAccuracy,
                 .snaplen = snaplen_ ?: kMaxSnapLen,
                 .network = kEthernet};
  dataWriter_->writeData(&hdr, sizeof(hdr));

  PcapMsg msg(nullptr, 0, 0);
  while (packetLimit_ == 0 || packetAmount_ < packetLimit_) {
    queue->blockingRead(msg);
    msg.trim(hdr.snaplen);
    if (msg.emptyMsg()) {
      LOG(INFO) << "Empty message was received. Writer thread is stopping.";
      break;
    }
    if (!dataWriter_->available(msg.getCapturedLen() + sizeof(pcaprec_hdr_s))) {
      LOG(INFO) << "DataWriter is full.";
      break;
    }
    writePacket(msg);
    ++packetAmount_;
  }
}

PcapWriter::FileWriter::FileWriter(const std::string &filename)
    : pcapFile_(filename.c_str(), O_RDWR | O_CREAT | O_TRUNC) {}

void PcapWriter::FileWriter::writeData(const void *ptr, size_t size) {
  folly::writeFull(pcapFile_.fd(), ptr, size);
  writtenBytes_ += size;
}

bool PcapWriter::FileWriter::available(size_t /* unused */) { return true; }

PcapWriter::ByteRangeWriter::ByteRangeWriter(folly::MutableByteRange &buffer)
    : buffer_(buffer) {}

void PcapWriter::ByteRangeWriter::writeData(const void *ptr, size_t size) {
  ::memcpy(static_cast<void *>(&(buffer_.front())), ptr, size);
  buffer_.advance(size);
  writtenBytes_ += size;
}

bool PcapWriter::ByteRangeWriter::available(size_t amount) {
  return buffer_.size() >= amount;
}

} // namespace xdpdump
