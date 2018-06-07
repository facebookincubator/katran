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

#ifndef __BALANCER_CONSTS_H
#define __BALANCER_CONSTS_H
/*
 * This file contains definition of all balancer specific constants
 */

// we dont want to do htons for each packet, so this is ETH_P_IPV6 and
// ETH_P_IP in be format
#define BE_ETH_P_IP 8
#define BE_ETH_P_IPV6 56710

// functions could return ether drop, pass, tx or we need to further
// process a packet to figure out what to do with it
#define FURTHER_PROCESSING -1

// 3FFF mask covers more fragments flag and fragment offset field.
// 65343 = 3FFF in BigEndian
#define PCKT_FRAGMENTED 65343

#define IPV4_HDR_LEN_NO_OPT 20
#define IPV4_PLUS_ICMP_HDR 28
#define IPV6_PLUS_ICMP_HDR 48

//consistent hashing ring size
#ifndef RING_SIZE
#define RING_SIZE 65537
#endif

#ifndef MAX_VIPS
#define MAX_VIPS 512
#endif

// 1 real is equal to 1 ip address. so server w/ v4 and v6 would most likely
// consume 2 spots
#ifndef MAX_REALS
#define MAX_REALS 4096
#endif

// we are using first 12bits from quic's connection id to store real's index
#define MAX_QUIC_REALS 4096

#define CTL_MAP_SIZE 16
#define CH_RINGS_SIZE (MAX_VIPS * RING_SIZE)
#define STATS_MAP_SIZE (MAX_VIPS * 2)

// for LRU's map in map we will support up to this number of cpus
#ifndef MAX_SUPPORTED_CPUS
#define MAX_SUPPORTED_CPUS 128
#endif

// default lru is a fallback lru, which will be used when forwarding cpu/core
// cannot find per core lru in lrus map-in-map.
// we should only have a hit in this default lru while running unittests.
// thats why by default the value of this lru is this small
#define DEFAULT_LRU_SIZE 1000

#define ONE_SEC 1000000000U // 1 sec in nanosec

// how long we will keep udp's connection as active in lru map. in nanosec
#ifndef LRU_UDP_TIMEOUT
#define LRU_UDP_TIMEOUT 30000000000U // 30 sec in nanosec
#endif

// FLAGS:
// real_definition flags:
// address is ipv6
#define F_IPV6 (1 << 0)
// vip_meta flags
// dont use client's port for hash calculation
#define F_HASH_NO_SRC_PORT (1 << 0)
// dont try to find existing connection in lru map and don't update it
#define F_LRU_BYPASS (1 << 1)
// use quic's connection id for the hash calculation
#define F_QUIC_VIP (1 << 2)
// use only dst port for the hash calculation
#define F_HASH_DPORT_ONLY (1 << 3)
// packet_description flags:
// the description has been created from icmp msg
#define F_ICMP (1 << 0)
// tcp packet had syn flag set
#define F_SYN_SET (1 << 1)

// ttl for outer ipip packet
#ifndef DEFAULT_TTL
#define DEFAULT_TTL 64
#endif

// from draft-ietf-quic-transport-05
#define QUIC_LONG_HEADER 0x80
#define QUIC_CLIENT_INITIAL 0x02
#define QUIC_0RTT 0x06
#define QUIC_CONN_ID_PRESENT 0x40
#define CLIENT_GENERATED_ID (QUIC_CLIENT_INITIAL | QUIC_0RTT)
// 1 byte public flags + 8 byte connection id
#define QUIC_HDR_SIZE 9

// max ethernet packet's size which destination is a vip
// we need to inforce it because if origin_packet + encap_hdr > MTU
// then, depends on the dirver, it could either panic or drop the packet
// for default value: 1500 ip size + 14 ether hdr size
#ifndef MAX_PCKT_SIZE
#define MAX_PCKT_SIZE 1514
#endif

// for v4 and v6: initial packet would be truncated to the size of eth header
// plus ipv4/ipv6 header and few bytes of payload
#define ICMP_TOOBIG_SIZE 98
#define ICMP6_TOOBIG_SIZE 262


#define ICMP6_TOOBIG_PAYLOAD_SIZE (ICMP6_TOOBIG_SIZE - 6)
#define ICMP_TOOBIG_PAYLOAD_SIZE (ICMP_TOOBIG_SIZE - 6)

#define NO_FLAGS 0

// offset of the lru cache hit related counters
#define LRU_CNTRS 0
#define LRU_MISS_CNTR 1
#define NEW_CONN_RATE_CNTR 2
#define FALLBACK_LRU_CNTR 3
//offset of icmp related counters
#define ICMP_TOOBIG_CNTRS 4

// max ammount of new connections per seconda per core for lru update
// if we go beyond this value - we will bypass lru update.
#ifndef MAX_CONN_RATE
#define MAX_CONN_RATE 125000
#endif

#ifndef IPIP_V4_PREFIX
// RFC1918: we are going to use 172.16/10 as our src (4268 is 172.16 in BE)
// for ipip header
#define IPIP_V4_PREFIX 4268
#endif

// for default values:
// RFC 6666: we are going to use 0100::/64 discard prefix as our src
// for ip(6)ip6 header

#ifndef IPIP_V6_PREFIX1
#define IPIP_V6_PREFIX1 1
#endif

#ifndef IPIP_V6_PREFIX2
#define IPIP_V6_PREFIX2 0
#endif

#ifndef IPIP_V6_PREFIX3
#define IPIP_V6_PREFIX3 0
#endif

// optional features (requires kernel support. turned off by default)
//#define ICMP_TOOBIG_GENERATION

#endif // of __BALANCER_CONSTS_H
