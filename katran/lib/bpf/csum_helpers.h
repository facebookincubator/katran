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

#ifndef __CSUM_HELPERS_H
#define __CSUM_HELPERS_H

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <stdbool.h>

#include "bpf.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"

__attribute__((__always_inline__)) static inline __u16 csum_fold_helper(
    __u64 csum) {
  int i;
#pragma unroll
  for (i = 0; i < 4; i++) {
    if (csum >> 16)
      csum = (csum & 0xffff) + (csum >> 16);
  }
  return ~csum;
}

__attribute__((__always_inline__)) static int min_helper(int a, int b) {
  return a < b ? a : b;
}

__attribute__((__always_inline__)) static inline void
ipv4_csum(void* data_start, int data_size, __u64* csum) {
  *csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
  *csum = csum_fold_helper(*csum);
}

__attribute__((__always_inline__)) static inline void ipv4_csum_inline(
    void* iph,
    __u64* csum) {
  __u16* next_iph_u16 = (__u16*)iph;
#pragma clang loop unroll(full)
  for (int i = 0; i < sizeof(struct iphdr) >> 1; i++) {
    *csum += *next_iph_u16++;
  }
  *csum = csum_fold_helper(*csum);
}

__attribute__((__always_inline__)) static inline void
ipv4_l4_csum(void* data_start, int data_size, __u64* csum, struct iphdr* iph) {
  __u32 tmp = 0;
  *csum = bpf_csum_diff(0, 0, &iph->saddr, sizeof(__be32), *csum);
  *csum = bpf_csum_diff(0, 0, &iph->daddr, sizeof(__be32), *csum);
  tmp = __builtin_bswap32((__u32)(iph->protocol));
  *csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
  tmp = __builtin_bswap32((__u32)(data_size));
  *csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
  *csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
  *csum = csum_fold_helper(*csum);
}

__attribute__((__always_inline__)) static inline void
ipv6_csum(void* data_start, int data_size, __u64* csum, struct ipv6hdr* ip6h) {
  // ipv6 pseudo header
  __u32 tmp = 0;
  *csum = bpf_csum_diff(0, 0, &ip6h->saddr, sizeof(struct in6_addr), *csum);
  *csum = bpf_csum_diff(0, 0, &ip6h->daddr, sizeof(struct in6_addr), *csum);
  tmp = __builtin_bswap32((__u32)(data_size));
  *csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
  tmp = __builtin_bswap32((__u32)(ip6h->nexthdr));
  *csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
  // sum over payload
  *csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
  *csum = csum_fold_helper(*csum);
}

#ifdef GUE_ENCAP

// Next four methods are helper methods to add or remove IP(6) pseudo header
// unto the given csum value.

__attribute__((__always_inline__)) static inline __s64 add_pseudo_ipv6_header(
    struct ipv6hdr* ip6h,
    __u64* csum) {
  __s64 ret;
  __u32 tmp = 0;
  ret = bpf_csum_diff(0, 0, &ip6h->saddr, sizeof(struct in6_addr), *csum);
  if (ret < 0) {
    return ret;
  }
  *csum = ret;
  ret = bpf_csum_diff(0, 0, &ip6h->daddr, sizeof(struct in6_addr), *csum);
  if (ret < 0) {
    return ret;
  }
  *csum = ret;
  // convert 16-bit payload in network order to 32-bit in network order
  // e.g. payload len: 0x0102 to be written as 0x02010000 in network order
  tmp = (__u32)bpf_ntohs(ip6h->payload_len);
  /* back to network byte order */
  tmp = bpf_htonl(tmp);
  ret = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
  if (ret < 0) {
    return ret;
  }
  *csum = ret;
  tmp = __builtin_bswap32((__u32)(ip6h->nexthdr));
  ret = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
  if (ret < 0) {
    return ret;
  }
  *csum = ret;
  return 0;
}

__attribute__((__always_inline__)) static inline __s64 rem_pseudo_ipv6_header(
    struct ipv6hdr* ip6h,
    __u64* csum) {
  __s64 ret;
  __u32 tmp = 0;
  ret = bpf_csum_diff(&ip6h->saddr, sizeof(struct in6_addr), 0, 0, *csum);
  if (ret < 0) {
    return ret;
  }
  *csum = ret;
  ret = bpf_csum_diff(&ip6h->daddr, sizeof(struct in6_addr), 0, 0, *csum);
  if (ret < 0) {
    return ret;
  }
  *csum = ret;
  tmp = (__u32)bpf_ntohs(ip6h->payload_len);
  tmp = bpf_htonl(tmp);
  ret = bpf_csum_diff(&tmp, sizeof(__u32), 0, 0, *csum);
  if (ret < 0) {
    return ret;
  }
  *csum = ret;
  tmp = __builtin_bswap32((__u32)(ip6h->nexthdr));
  ret = bpf_csum_diff(&tmp, sizeof(__u32), 0, 0, *csum);
  if (ret < 0) {
    return ret;
  }
  *csum = ret;
  return 0;
}

__attribute__((__always_inline__)) static inline __s64 add_pseudo_ipv4_header(
    struct iphdr* iph,
    __u64* csum) {
  __s64 ret;
  __u32 tmp = 0;
  ret = bpf_csum_diff(0, 0, &iph->saddr, sizeof(__be32), *csum);
  if (ret < 0) {
    return ret;
  }
  *csum = ret;
  ret = bpf_csum_diff(0, 0, &iph->daddr, sizeof(__be32), *csum);
  if (ret < 0) {
    return ret;
  }
  *csum = ret;
  tmp = (__u32)bpf_ntohs(iph->tot_len) - sizeof(struct iphdr);
  tmp = bpf_htonl(tmp);
  ret = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
  if (ret < 0) {
    return ret;
  }
  *csum = ret;
  tmp = __builtin_bswap32((__u32)(iph->protocol));
  ret = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
  if (ret < 0) {
    return ret;
  }
  *csum = ret;
  return 0;
}

__attribute__((__always_inline__)) static inline __s64 rem_pseudo_ipv4_header(
    struct iphdr* iph,
    __u64* csum) {
  __s64 ret;
  __u32 tmp = 0;
  ret = bpf_csum_diff(&iph->saddr, sizeof(__be32), 0, 0, *csum);
  if (ret < 0) {
    return ret;
  }
  *csum = ret;
  ret = bpf_csum_diff(&iph->daddr, sizeof(__be32), 0, 0, *csum);
  if (ret < 0) {
    return ret;
  }
  *csum = ret;
  tmp = (__u32)bpf_ntohs(iph->tot_len) - sizeof(struct iphdr);
  tmp = bpf_htonl(tmp);
  ret = bpf_csum_diff(&tmp, sizeof(__u32), 0, 0, *csum);
  if (ret < 0) {
    return ret;
  }
  *csum = ret;
  tmp = __builtin_bswap32((__u32)(iph->protocol));
  ret = bpf_csum_diff(&tmp, sizeof(__u32), 0, 0, *csum);
  if (ret < 0) {
    return ret;
  }
  *csum = ret;
  return 0;
}

/*
 * The following methods concern computation of checksum for GUE encapsulated
 * header for various combination of ip-headers.
 *
 * csum computation for the GUE header is implemented as the Eqn 3 in RFC-1624
 * https://tools.ietf.org/html/rfc1624#section-2
 * New checksum (HC') = ~(~HC + ~m + m')
 * where: HC  - old checksum in header
 *        HC' - new checksum in header
 *        m   - old value of a 16-bit field
 *        m'  - new value of a 16-bit field
 */
__attribute__((__always_inline__)) static inline bool gue_csum_v6(
    struct ipv6hdr* outer_ip6h,
    struct udphdr* udph,
    struct ipv6hdr* inner_ip6h,
    __u64* csum_in_hdr) {
  __s64 ret;
  __u32 tmp = 0;
  // one's complement of csum from the original transport header
  __u32 seed = (~(*csum_in_hdr)) & 0xffff;
  // add the original csum value from the transport header
  __u32 orig_csum = (__u32)*csum_in_hdr;
  ret = bpf_csum_diff(0, 0, &orig_csum, sizeof(__u32), seed);
  if (ret < 0) {
    return false;
  }
  *csum_in_hdr = ret;
  if (rem_pseudo_ipv6_header(inner_ip6h, csum_in_hdr) < 0) {
    return false;
  }
  ret = bpf_csum_diff(0, 0, inner_ip6h, sizeof(struct ipv6hdr), *csum_in_hdr);
  if (ret < 0) {
    return false;
  }
  *csum_in_hdr = ret;
  ret = bpf_csum_diff(0, 0, udph, sizeof(struct udphdr), *csum_in_hdr);
  if (ret < 0) {
    return false;
  }
  *csum_in_hdr = ret;
  if (add_pseudo_ipv6_header(outer_ip6h, csum_in_hdr) < 0) {
    return false;
  }
  *csum_in_hdr = csum_fold_helper(*csum_in_hdr);
  return true;
}

__attribute__((__always_inline__)) static inline bool gue_csum_v4(
    struct iphdr* outer_iph,
    struct udphdr* udph,
    struct iphdr* inner_iph,
    __u64* csum_in_hdr) {
  __s64 ret;
  __u32 tmp = 0;
  __u32 seed = (~(*csum_in_hdr)) & 0xffff;
  __u32 orig_csum = (__u32)*csum_in_hdr;
  ret = bpf_csum_diff(0, 0, &orig_csum, sizeof(__u32), seed);
  if (ret < 0) {
    return false;
  }
  *csum_in_hdr = ret;
  if (rem_pseudo_ipv4_header(inner_iph, csum_in_hdr) < 0) {
    return false;
  }
  ret = bpf_csum_diff(0, 0, inner_iph, sizeof(struct iphdr), *csum_in_hdr);
  if (ret < 0) {
    return false;
  }
  *csum_in_hdr = ret;
  ret = bpf_csum_diff(0, 0, udph, sizeof(struct udphdr), *csum_in_hdr);
  if (ret < 0) {
    return false;
  }
  *csum_in_hdr = ret;
  if (add_pseudo_ipv4_header(outer_iph, csum_in_hdr) < 0) {
    return false;
  }
  *csum_in_hdr = csum_fold_helper(*csum_in_hdr);
  return true;
}

__attribute__((__always_inline__)) static inline bool gue_csum_v4_in_v6(
    struct ipv6hdr* outer_ip6h,
    struct udphdr* udph,
    struct iphdr* inner_iph,
    __u64* csum_in_hdr) {
  __s64 ret;
  __u32 tmp = 0;
  __u32 seed = (~(*csum_in_hdr)) & 0xffff;
  __u32 orig_csum = (__u32)*csum_in_hdr;
  ret = bpf_csum_diff(0, 0, &orig_csum, sizeof(__u32), seed);
  if (ret < 0) {
    return false;
  }
  *csum_in_hdr = ret;
  if (rem_pseudo_ipv4_header(inner_iph, csum_in_hdr) < 0) {
    return false;
  }
  ret = bpf_csum_diff(0, 0, inner_iph, sizeof(struct iphdr), *csum_in_hdr);
  if (ret < 0) {
    return false;
  }
  *csum_in_hdr = ret;
  ret = bpf_csum_diff(0, 0, udph, sizeof(struct udphdr), *csum_in_hdr);
  if (ret < 0) {
    return false;
  }
  *csum_in_hdr = ret;
  if (add_pseudo_ipv6_header(outer_ip6h, csum_in_hdr) < 0) {
    return false;
  }
  *csum_in_hdr = csum_fold_helper(*csum_in_hdr);
  return true;
}
#endif // of GUE_ENCAP

#endif // of __CSUM_HELPERS_H
