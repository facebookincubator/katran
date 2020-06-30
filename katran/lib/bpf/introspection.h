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

// if KATRAN_INTROSPECTION is enabled
#define MAX_EVENT_SIZE 128

// introspection events, they are defined regardless because they are used in
// constants which does not depend on the introspection flag
#define TCP_NONSYN_LRUMISS 0
#define PACKET_TOOBIG 1

#ifdef KATRAN_INTROSPECTION
// Introspection enabled, enable helpers
#define REPORT_EVENT(xdp, event, data, size, meta_only)         \
({                                                              \
               submit_event((xdp), &event_pipe, (event),        \
                            data, size, meta_only);             \
})
#define REPORT_TCP_NONSYN_LRUMISS(xdp, data, size, meta_only)   \
               REPORT_EVENT(xdp, TCP_NONSYN_LRUMISS,            \
                            data, size, meta_only)
#define REPORT_PACKET_TOOBIG(xdp, data, size, meta_only)          \
               REPORT_EVENT(xdp, PACKET_TOOBIG,                   \
                            data, size, meta_only)
#else
// Introspection disabled, define helpers to be nop
#define REPORT_TCP_NONSYN_LRUMISS(...) {}
#define REPORT_PACKET_TOOBIG(...) {}
#endif
