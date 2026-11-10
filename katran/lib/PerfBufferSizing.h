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
#include <limits>

namespace katran {
namespace detail {

inline size_t getPerfBufferPageCount(size_t pages4K, size_t nativePageSize) {
  constexpr size_t kConfiguredPageSize = 4096;
  if (pages4K == 0 || (pages4K & (pages4K - 1)) != 0 || nativePageSize == 0 ||
      (nativePageSize & (nativePageSize - 1)) != 0 ||
      pages4K > std::numeric_limits<size_t>::max() / kConfiguredPageSize) {
    return 0;
  }
  const auto bytes = pages4K * kConfiguredPageSize;
  return bytes / nativePageSize + (bytes % nativePageSize != 0);
}

} // namespace detail
} // namespace katran
