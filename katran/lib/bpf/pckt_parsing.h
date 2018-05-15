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

#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/icmp.h>
#include <uapi/linux/icmpv6.h>
#include <stddef.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>

#include "balancer_consts.h"

struct quic_header {
  __u8 flags;
  __u64 connection_id;
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
  struct quic_header *q_hdr;
  int flags;
  // offset points to the beginning of transport header (udp)
  // of quic's packet
  if ((data + off + sizeof(struct udphdr) +
       sizeof(struct quic_header)) > data_end) {
    return FURTHER_PROCESSING;
  }

  q_hdr = data + off + sizeof(struct udphdr);
  flags = q_hdr->flags;
  if ((flags & (QUIC_LONG_HEADER | CLIENT_GENERATED_ID)) > QUIC_LONG_HEADER) {
    // this is long header but with client's generated connection id.
    return FURTHER_PROCESSING;
  }
  if (!(flags & QUIC_LONG_HEADER)) {
    // short header
    if (!(flags & QUIC_CONN_ID_PRESENT)) {
      // but w/o connection-id
      return FURTHER_PROCESSING;
    }
  }
  // either long header which always has connection id; or short one but id
  // presents. we use first 12 bits of connection-id as index for real.
  // connection-id field size is 64 bits
  return ((q_hdr->connection_id) >> 52);
}

#endif // of  __PCKT_PARSING_H
