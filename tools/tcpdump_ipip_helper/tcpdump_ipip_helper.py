#!/usr/bin/env python3
# Copyright (C) 2018-present, Facebook, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import argparse
import ipaddress
import struct

CHUNK_SIZE = 10
EMPTY_FILTER = 2
V4_HDR_SIZE = 20
V6_HDR_SIZE = 40
V4_SRC_OFFSET = 12
V4_DST_OFFSET = 16
V4_PROTO_OFFSET = 9
SPORT_OFFSET = 0
DPORT_OFFSET = 2
V6_SRC_OFFSET = 8
V6_DST_OFFSET = 24
V6_PROTO_OFFSET = 6
V4_ADDR_SIZE = 4
V6_PART_SIZE = 4
PROTO_SIZE = 1
PORT_SIZE = 2


def ipv4_in_hex(addr):
    """
    @param string addr ipv4 address
    @return string hex representation of this address
    """
    return "0x{:08X}".format(int(ipaddress.ip_address(addr)))


def ip6_exploded(addr):
    """
    @param string addr ipv6 address
    @return list<string> ipv6 addresses splited into 4 groups by 32bit each
    """
    return [
        "0x{:04X}".format(x)
        for x in struct.unpack("!IIII", ipaddress.ip_address(addr).packed)
    ]


def modify_filter(tcpdump_filters, value, offset, size, v6=False):
    """
    @param list<string> tcpdump_filter list of currently generated filters
    @param string value to match
    @param int offset offset of this value in the packet
    @param int size of the value in bytes
    @param bool v6 flag if the filter is related to ipv6 packet
    @return modified tcpdump_filter
    """
    packet_type = "ip"
    if v6:
        packet_type = "ip6"
    tcpdump_filters.append(
        "({}[{}:{}] == {} )".format(packet_type, offset, size, value)
    )
    return tcpdump_filters


def create_tcpdump_line_v6(args):
    """
    @param args cli arguments
    @return None
    IPv6 Header Format

   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version| Traffic Class |           Flow Label                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Payload Length        |  Next Header  |   Hop Limit   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                                                               +
   |                                                               |
   +                         Source Address                        +
   |                                                               |
   +                                                               +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                                                               +
   |                                                               |
   +                      Destination Address                      +
   |                                                               |
   +                                                               +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    tcpdump_filters = []
    if args.src:
        chunk_offset = 0
        for v6_chunk in ip6_exploded(args.src):
            tcpdump_filters = modify_filter(
                tcpdump_filters,
                v6_chunk,
                V6_HDR_SIZE + V6_SRC_OFFSET + chunk_offset,
                V6_PART_SIZE,
                True,
            )
            chunk_offset += V6_PART_SIZE
    if args.dst:
        chunk_offset = 0
        for v6_chunk in ip6_exploded(args.dst):
            tcpdump_filters = modify_filter(
                tcpdump_filters,
                v6_chunk,
                V6_HDR_SIZE + V6_DST_OFFSET + chunk_offset,
                V6_PART_SIZE,
                True,
            )
            chunk_offset += V6_PART_SIZE
    if args.proto:
        tcpdump_filters = modify_filter(
            tcpdump_filters, args.proto, V6_HDR_SIZE + V6_PROTO_OFFSET, PROTO_SIZE, True
        )
    if args.sport:
        tcpdump_filters = modify_filter(
            tcpdump_filters, args.sport, 2 * V6_HDR_SIZE + SPORT_OFFSET, PORT_SIZE, True
        )
    if args.dport:
        tcpdump_filters = modify_filter(
            tcpdump_filters, args.dport, 2 * V6_HDR_SIZE + DPORT_OFFSET, PORT_SIZE, True
        )
    print('"(' + " and ".join(tcpdump_filters) + ')"')


def create_tcpdump_line_v4(args, offset):
    """
    @param object args cli arguments
    @param int offset of internal header compare to external one
    @return None

    IP header format:
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    tcpdump_filters = []
    if args.src:
        tcpdump_filters = modify_filter(
            tcpdump_filters,
            ipv4_in_hex(args.src),
            offset + V4_SRC_OFFSET,
            V4_ADDR_SIZE,
            offset == V6_HDR_SIZE,
        )
    if args.dst:
        tcpdump_filters = modify_filter(
            tcpdump_filters,
            ipv4_in_hex(args.dst),
            offset + V4_DST_OFFSET,
            V4_ADDR_SIZE,
            offset == V6_HDR_SIZE,
        )
    if args.proto:
        tcpdump_filters = modify_filter(
            tcpdump_filters,
            args.proto,
            offset + V4_PROTO_OFFSET,
            PROTO_SIZE,
            offset == V6_HDR_SIZE,
        )
    if args.sport:
        tcpdump_filters = modify_filter(
            tcpdump_filters,
            args.sport,
            offset + V4_HDR_SIZE + SPORT_OFFSET,
            PORT_SIZE,
            offset == V6_HDR_SIZE,
        )
    if args.dport:
        tcpdump_filters = modify_filter(
            tcpdump_filters,
            args.dport,
            offset + V4_HDR_SIZE + DPORT_OFFSET,
            PORT_SIZE,
            offset == V6_HDR_SIZE,
        )
    print('"(' + " and ".join(tcpdump_filters) + ')"')


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "this is a tool which helps to create a filter to match "
            "fields from internal header of IPIP packet"
        )
    )
    parser.add_argument(
        "-m",
        "--mode",
        choices=["4", "6", "46"],
        help=(
            "mode of the filter. possible values: 4 (for ipip) "
            "6 (for ip6ip6), 46 (for ip4ip6)"
        ),
    )
    parser.add_argument(
        "-s",
        "--src",
        default=None,
        help="src ip address of internal packet. could be ipv4 or ipv6",
    )
    parser.add_argument(
        "-d",
        "--dst",
        default=None,
        help="dst ip address of internal packet. could be ipv4 or ipv6",
    )
    parser.add_argument(
        "-p",
        "--proto",
        default=None,
        type=int,
        help=(
            "protocol of internal packet. must be a number. "
            "e.g. 6 for tcp or 17 for udp"
        ),
    )
    parser.add_argument(
        "--sport",
        default=None,
        type=int,
        help="src port of internal packet (e.g. if it's udp or tcp)",
    )
    parser.add_argument(
        "--dport",
        default=None,
        type=int,
        help="dst port of internal packet (e.g. if it's udp or tcp)",
    )

    return parser.parse_args()


def main():
    args = parse_args()
    if args.mode == "4":
        create_tcpdump_line_v4(args, V4_HDR_SIZE)
    elif args.mode == "6":
        create_tcpdump_line_v6(args)
    elif args.mode == "46":
        create_tcpdump_line_v4(args, V6_HDR_SIZE)


if __name__ == "__main__":
    main()
