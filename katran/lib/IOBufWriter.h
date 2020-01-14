/* Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved
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
#include <folly/io/IOBuf.h>

#include "katran/lib/DataWriter.h"

namespace katran {

/**
 * IOBufWriter is used to write pcap-data into IOBuf.
 */
class IOBufWriter : public DataWriter {
 public:
  /**
   * @param unique_ptr<IOBuf> iobuf for packets to written into
   */
  explicit IOBufWriter(folly::IOBuf* iobuf);

  void writeData(const void* ptr, std::size_t size) override;

  bool available(std::size_t amount) override;

  bool restart() override;

  bool stop() override {return true;}

 private:
  folly::IOBuf* iobuf_;
};

} // namespace katran
