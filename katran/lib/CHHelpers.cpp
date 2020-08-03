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

#include "katran/lib/CHHelpers.h"
#include "katran/lib/MaglevHash.h"
namespace katran {
std::unique_ptr<ConsistentHash> CHHelpers::hashFunctionsFactory(
    HashFunctions func) {
  switch (func) {
    case HashFunctions::Maglev:
      return std::make_unique<MaglevHash>();
    default:
      // fallback to default maglev's implementation
      return std::make_unique<MaglevHash>();
  }
}
} // namespace katran
