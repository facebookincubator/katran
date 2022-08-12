/* Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved.
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

#ifndef __FLOW_DEBUG_H
#define __FLOW_DEBUG_H

#ifdef RECORD_FLOW_INFO

#ifndef FLOW_DEBUG_MAP_SIZE
#define FLOW_DEBUG_MAP_SIZE 1000000
#endif // of FLOW_DEBUG_MAP_SIZE

#define NO_FLAGS 0

#include "flow_debug_helpers.h"

// Flow debug enabled, enable helpers
#define RECORD_GUE_ROUTE(old_eth, new_eth, data_end, outer_v4, inner_v4) \
  gue_record_route(old_eth, new_eth, data_end, outer_v4, inner_v4)

#else

// Flow debug disabled, define helpers to be noop
#define RECORD_GUE_ROUTE(...) \
  {}

#endif // of RECORD_FLOW_INFO

#endif // of __FLOW_DEBUG_H
