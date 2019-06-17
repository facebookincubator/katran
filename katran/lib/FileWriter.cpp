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

#include "katran/lib/FileWriter.h"
#include <folly/FileUtil.h>
#include <glog/logging.h>

namespace katran {

FileWriter::FileWriter(const std::string& filename)
    : pcapFile_(filename.c_str(), O_RDWR | O_CREAT | O_TRUNC) {
      filename_ = filename;
    }

void FileWriter::writeData(const void* ptr, std::size_t size) {
  auto successfullyWritten = folly::writeFull(pcapFile_.fd(), ptr, size);
  if (successfullyWritten < 0) {
    LOG(ERROR) << "Error while trying to write to pcap file: "
               << filename_;
  } else {
    writtenBytes_ += size;
  }
}

bool FileWriter::available(size_t /* unused */) {
  return true;
}

bool FileWriter::stop() {
  pcapFile_.closeNoThrow();
  return true;
}

bool FileWriter::restart() {
  pcapFile_.closeNoThrow();
  pcapFile_ = folly::File(filename_.c_str(), O_RDWR | O_CREAT | O_TRUNC);
  return true;
}

} // namespace katran
