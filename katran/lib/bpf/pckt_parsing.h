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
  // Pre draft-22: Dest Conn Id Len(4 bits) | Source Conn Id Len(4 bits)
  // Post draft-22: Dest Conn Id Len (8 bits)
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

__attribute__((__always_inline__))
static inline __u64 calc_offset(bool is_ipv6, bool is_icmp) {
  __u64 off = sizeof(struct ethhdr);
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

#ifdef TCP_SERVER_ID_ROUTING
__attribute__((__always_inline__)) static inline int tcp_hdr_opt_lookup(
    void* data,
    void* data_end,
    bool is_ipv6,
    struct real_definition** real,
    struct packet_description* pckt,
    bool bypass_lru,
    void* lru_map) {
  struct real_pos_lru* dst_lru;
  struct tcphdr* tcp_hdr;
  void* tcp_opt;
  __u8 tcp_hdr_opt_len = 0;
  __u8 hdr_bytes_parsed = 0;
  __u64 tcp_offset = 0;
  __u32 server_id = 0;

  tcp_offset = calc_offset(is_ipv6, false /* is_icmp */);
  tcp_hdr = (struct tcphdr*)(data + tcp_offset);
  if (tcp_hdr + 1 > data_end) {
    return FURTHER_PROCESSING;
  }
  tcp_hdr_opt_len = (tcp_hdr->doff * 4) - sizeof(struct tcphdr);
  if (tcp_hdr_opt_len < TCP_HDR_OPT_LEN_TPR) {
    return FURTHER_PROCESSING;
  }
  tcp_opt = data + tcp_offset + sizeof(struct tcphdr);

#pragma clang loop unroll(full)
  for (int i = 0; i < TCP_HDR_OPT_MAX_OPT_CHECKS; i++) {
    if (tcp_opt + 1 > data_end) {
      return FURTHER_PROCESSING;
    }
    if (hdr_bytes_parsed + 1 > tcp_hdr_opt_len) {
      return FURTHER_PROCESSING;
    }
    __u8* kind = (__u8*)tcp_opt;
    // 1 byte options
    if (*kind == TCP_OPT_EOL) {
      // EOL signifies end of options
      return FURTHER_PROCESSING;
    }
    if (*kind == TCP_OPT_NOP) {
      tcp_opt = (void*)(kind + sizeof(__u8));
      hdr_bytes_parsed += sizeof(__u8);
      continue;
    }
    if (kind + sizeof(__u8) + sizeof(__u8) > data_end) {
      return FURTHER_PROCESSING;
    }
    __u8 hdr_len = *(kind + sizeof(__u8));
    if (kind + hdr_len > data_end) {
      return FURTHER_PROCESSING;
    }
    if (*kind == TCP_HDR_OPT_KIND_TPR) {
      if (hdr_len != TCP_HDR_OPT_LEN_TPR) {
        return FURTHER_PROCESSING;
      }
      __u8* hdr_data_off = kind + sizeof(__u8) + sizeof(__u8);
      if (hdr_data_off + sizeof(__u32) > data_end) {
        return FURTHER_PROCESSING;
      }
      server_id = *((__u32*)(hdr_data_off));
      break;
    }
    hdr_bytes_parsed += hdr_len;
    tcp_opt = (void*)(kind + hdr_len);
  }

  if (!server_id) {
    return FURTHER_PROCESSING;
  }

  __u32 key = server_id;
  __u32* real_pos = bpf_map_lookup_elem(&server_id_map, &key);
  if (!real_pos) {
    return FURTHER_PROCESSING;
  }
  key = *real_pos;
  if (key == 0) {
    // Since server_id_map is a bpf_map_array all its members are 0-initialized
    // This can lead to a false match for non-existing key to real at index 0.
    // So, just skip key of value 0 to avoid misrouting of packets.
    return FURTHER_PROCESSING;
  }
  pckt->real_index = key;
  *real = bpf_map_lookup_elem(&reals, &key);
  if (!(*real)) {
    return FURTHER_PROCESSING;
  }
  // update this routing decision in the lru_map as well
  if (!bypass_lru) {
    struct real_pos_lru *dst_lru = bpf_map_lookup_elem(lru_map, &pckt->flow);
    if (dst_lru) {
      dst_lru->pos = key;
      return 0;
    }
    struct real_pos_lru new_dst_lru = {};
    new_dst_lru.pos = key;
    bpf_map_update_elem(lru_map, &pckt->flow, &new_dst_lru, BPF_ANY);
  }
  return 0;
}
#endif // TCP_SERVER_ID_ROUTING

__attribute__((__always_inline__))
static inline int parse_quic(void *data, void *data_end,
                             bool is_ipv6, struct packet_description *pckt) {
  bool is_icmp = (pckt->flags & F_ICMP);
  __u64 off = calc_offset(is_ipv6, is_icmp);
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
    // Post draft version 22, this byte is the conn id length of dest conn id
    if (long_header->conn_id_lens < QUIC_MIN_CONNID_LEN) {
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
  // connId schema: if first two bits contain the right version info
  __u8 connIdVersion = (connId[0] >> 6);
  if (connIdVersion == QUIC_CONNID_VERSION_V1) {
    // extract last 16 bits from the first 18 bits:
    //            last 6 bits         +    8 bits        +   first 2 bits
    return ((connId[0] & 0x3F) << 10) | (connId[1] << 2) | (connId[2] >> 6);
  } else if (connIdVersion == QUIC_CONNID_VERSION_V2) {
    __u32 cid = (connId[1] << 16) | (connId[2] << 8) | (connId[3]);
    return cid;
  }
  return FURTHER_PROCESSING;
}

#endif // of  __PCKT_PARSING_H
