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
#include <cstddef>

namespace katran {

/**
 * class which implements interface, used by PcapWriter to write data, received
 * from katran
 */

class DataWriter {
 public:
  virtual ~DataWriter() {}

  /**
   * @param const void *ptr data to write
   * std::size_t size of the data
   *
   * called when data needs to be written
   */
  virtual void writeData(const void* ptr, std::size_t size) = 0;

  /**
   * @param amount -- amount of bytes to write.
   *
   * Check if we're able to write `amount` bytes into storage. Returns true
   * if yes.
   */
  virtual bool available(std::size_t amount) = 0;

  /**
   * reset data writer. so if we would start to writeData again - it wont be
   * appended to existing one.
   */
  virtual bool restart() = 0;

  /**
   * stop writing data. flush everything which was not yet flushed, into storage
   */
  virtual bool stop() = 0;

  /**
   * @return std::size_t bytes which has been already written
   */
  std::size_t writtenBytes() {
    return writtenBytes_;
  }

 protected:
  /**
   * size_t wryteBytes is used to record amount of bytes that already
   * have been written.
   */
  std::size_t writtenBytes_{0};
};

} // namespace katran
