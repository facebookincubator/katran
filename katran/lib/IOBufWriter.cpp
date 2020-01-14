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

#include "katran/lib/IOBufWriter.h"
#include <cstring>

namespace katran {

IOBufWriter::IOBufWriter(folly::IOBuf* iobuf)
    : iobuf_(iobuf) {}

void IOBufWriter::writeData(const void* ptr, std::size_t size) {
  ::memcpy(static_cast<void*>(iobuf_->writableTail()), ptr, size);
  iobuf_->append(size);
}

bool IOBufWriter::available(std::size_t amount) {
  return iobuf_->tailroom() >= amount;
}

bool IOBufWriter::restart() {
  iobuf_->clear();
  return true;
}

} // namespace katran
