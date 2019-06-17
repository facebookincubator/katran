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

#include <folly/File.h>
#include <string>

#include "katran/lib/DataWriter.h"

namespace katran {
/**
 * FileWriter is used to write pcap-data into file.
 */
class FileWriter : public DataWriter {
 public:
  /**
   * @param const string filename where we are going to write data
   */
  explicit FileWriter(const std::string& filename);

  void writeData(const void* ptr, std::size_t size) override;

  bool available(std::size_t amount) override;

  bool restart() override;

  bool stop() override;

 private:
  folly::File pcapFile_;
  std::string filename_;
};

} // namespace katran
