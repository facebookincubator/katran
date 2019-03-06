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

#ifndef __PCKT_PARSING_H
#define __PCKT_PARSING_H

/*
 * This file contains generic packet parsing routines (e.g. tcp/udp headers
 * parsing etc)
 */

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <stddef.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/ptrace.h>
#include <stdbool.h>

#include "balancer_consts.h"
#include "balancer_helpers.h"
#include "bpf.h"

struct quic_long_header {
  __u8 flags;
  __u32 version;
  // Dest Conn Id Len(4 bits)| Source Conn Id Len(4 bits)
  __u8 conn_id_lens;
  // conn-id len can be of either 0 bytes in length or between 4 and 18 bytes
  // For routing, katran requires minimum of 'QUIC_MIN_CONNID_LEN',
  // and doesn't read beyond that
  __u8 dst_connection_id[QUIC_MIN_CONNID_LEN];
} __attribute__((__packed__));

struct quic_short_header {
  __u8 flags;
  __u8 connection_id[QUIC_MIN_CONNID_LEN];
} __attribute__((__packed__));

struct eth_hdr {
  unsigned char eth_dest[ETH_ALEN];
  unsigned char eth_source[ETH_ALEN];
  unsigned short  eth_proto;
};

__attribute__((__always_inline__))
static inline __u64 calc_offset(bool is_ipv6, bool is_icmp) {
  __u64 off = sizeof(struct eth_hdr);
  if (is_ipv6) {
    off += sizeof(struct ipv6hdr);
    if (is_icmp) {
      off += (sizeof(struct icmp6hdr) + sizeof(struct ipv6hdr));
    }
  } else {
    off += sizeof(struct iphdr);
    if (is_icmp) {
      off += (sizeof(struct icmphdr) + sizeof(struct iphdr));
    }
  }
  return off;
}

__attribute__((__always_inline__))
static inline bool parse_udp(void *data, void *data_end,
                             bool is_ipv6,
                             struct packet_description *pckt) {

  bool is_icmp = !((pckt->flags & F_ICMP) == 0);
  __u64 off = calc_offset(is_ipv6, is_icmp);
  struct udphdr *udp;
  udp = data + off;

  if (udp + 1 > data_end) {
    return false;
  }

  if (!is_icmp) {
    pckt->flow.port16[0] = udp->source;
    pckt->flow.port16[1] = udp->dest;
  } else {
    // packet_description was created from icmp "packet too big". hence
    // we need to invert src/dst ports
    pckt->flow.port16[0] = udp->dest;
    pckt->flow.port16[1] = udp->source;
  }
  return true;
}

__attribute__((__always_inline__))
static inline bool parse_tcp(void *data, void *data_end,
                             bool is_ipv6,
                             struct packet_description *pckt) {

  bool is_icmp = !((pckt->flags & F_ICMP) == 0);
  __u64 off = calc_offset(is_ipv6, is_icmp);
  struct tcphdr *tcp;
  tcp = data + off;

  if (tcp + 1 > data_end) {
    return false;
  }

  if (tcp->syn) {
    pckt->flags |= F_SYN_SET;
  }

  if (!is_icmp) {
    pckt->flow.port16[0] = tcp->source;
    pckt->flow.port16[1] = tcp->dest;
  } else {
    // packet_description was created from icmp "packet too big". hence
    // we need to invert src/dst ports
    pckt->flow.port16[0] = tcp->dest;
    pckt->flow.port16[1] = tcp->source;
  }
  return true;
}

__attribute__((__always_inline__))
static inline int parse_quic(void *data, void *data_end,
                             bool is_ipv6, struct packet_description *pckt) {

  bool is_icmp = (pckt->flags & F_ICMP);
  __u64 off = calc_offset(is_ipv6, is_icmp);
  int flags;
  // offset points to the beginning of transport header (udp) of quic's packet
  /*                                      |QUIC PKT TYPE|           */
  if ((data + off + sizeof(struct udphdr) + sizeof(__u8)) > data_end) {
    return FURTHER_PROCESSING;
  }

  __u8* quic_data = data + off + sizeof(struct udphdr);
  __u8* pkt_type = quic_data;
  __u8* connId = NULL;
  // the position of conn id varies depending on whether the packet has a
  // long-header or short-header.
  // Once we compute the offset of conn id, just read fixed length,
  // even if the connid len can be of 0 or 4-18 bytes, since katran is only
  // concerned about the first 16 bits in Dest Conn Id
  if ((*pkt_type & QUIC_LONG_HEADER) == QUIC_LONG_HEADER) {
    // packet with long header
    if (quic_data + sizeof(struct quic_long_header) > data_end) {
      return FURTHER_PROCESSING;
    }
    if ((*pkt_type & QUIC_PACKET_TYPE_MASK) < QUIC_HANDSHAKE) {
      // for client initial and 0rtt packet - fall back to use c. hash, since
      // the connection-id is not the server-chosen one.
      return FURTHER_PROCESSING;
    }

    struct quic_long_header* long_header = (struct quic_long_header*) quic_data;
    // first 4 bits in the conn Id specifies the length of 'dest conn id'
    if ((long_header->conn_id_lens >> 4) < QUIC_MIN_CONNID_LEN) {
      // conn id is not long enough
      return FURTHER_PROCESSING;
    }
    connId = long_header->dst_connection_id;
  } else {
    // short header: just read the connId
    if (quic_data + sizeof(struct quic_short_header) > data_end) {
      return FURTHER_PROCESSING;
    }
    connId = ((struct quic_short_header*)quic_data)->connection_id;
  }
  if (!connId) {
    return FURTHER_PROCESSING;
  }
  // connId schema v2: if first two bits contain the right version info
  if ((connId[0] >> 6) == QUIC_CONNID_VERSION) {
    // extract last 16 bits from the first 18 bits:
    //            last 6 bits         +    8 bits        +   first 2 bits
    return ((connId[0] & 0x3F) << 10) | (connId[1] << 2) | (connId[2] >> 6);
  }
  return FURTHER_PROCESSING;
}

#endif // of  __PCKT_PARSING_H
