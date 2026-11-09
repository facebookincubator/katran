#pragma once

#include <bpf/vmlinux/vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include <katran/kde/bpf/kde_constants.h>
#include <katran/kde/bpf/kde_types.h>
#include <katran/kde/bpf/kde_utils.h>

#include <string.h>

// from uapi/linux/in6.h
#define IPPROTO_HOPOPTS 0
#define IPV6_TLV_JUMBO 194
// copy of hop_jumbo_hdr from vmlinux.h (removed in kernels >= 7.0)
struct kde_hop_jumbo_hdr {
  __u8 nexthdr;
  __u8 hdrlen;
  __u8 tlv_type;
  __u8 tlv_len;
  __be32 jumbo_payload_len;
};

// for outer ipip packet
#define DEFAULT_TOS 0
#define DEFAULT_TTL 64

#define V6DADDR (1 << 0)

#include "common/bpf/bpf_net_helpers.h"

#define GUE_DPORT 9886
#define GUE_DPORT_KDE 9887
#define IS_VALID_GUE_DPORT(port) \
  ((port) == GUE_DPORT || (port) == GUE_DPORT_KDE)
#define GUE_CSUM 0

#define COPY_INNER_PACKET_TOS 1

// from linux/pkt_cls.h
#define TC_ACT_UNSPEC (-1)
#define TC_ACT_SHOT 2

extern struct kde_tc_stats g_tc_stats[MAX_CPUS];

__attribute__((__always_inline__)) static inline __be16 gue_sport(__u32 seed) {
  // force a port above 1024
  return bpf_htons((seed ^ (seed >> 16)) | 0x0400);
}

__attribute__((__always_inline__)) static inline void create_udp_hdr(
    struct udphdr* udph,
    __be16 sport,
    __u16 dport,
    __u16 len,
    __u16 csum) {
  udph->source = sport;
  udph->dest = bpf_htons(dport);
  udph->len = bpf_htons(len);
  udph->check = csum;
}

__attribute__((__always_inline__)) static inline void create_v6_hdr(
    struct ipv6hdr* ip6h,
    __u8 priority,
    const __u8 (*flow_lbl)[3],
    const volatile __be32* saddr,
    const __be32* daddr,
    __u16 payload_len,
    __u8 proto,
    __u8 hop_limit) {
  ip6h->version = 6;
  __builtin_memset(ip6h->flow_lbl, 0, sizeof(ip6h->flow_lbl));
#ifdef COPY_INNER_PACKET_TOS
  ip6h->priority = priority;
  ip6h->flow_lbl[0] = (*flow_lbl)[0];
#else
  ip6h->priority = DEFAULT_TOS;
  ip6h->flow_lbl[0] = (*flow_lbl)[0] & 0x0F;
#endif
  ip6h->flow_lbl[1] = (*flow_lbl)[1];
  ip6h->flow_lbl[2] = (*flow_lbl)[2];
  ip6h->nexthdr = proto;
  ip6h->payload_len = bpf_htons(payload_len);
  ip6h->hop_limit = hop_limit;
  // memcpy with volatile const gets optimized out by compiler
  // __builtin_memcpy(ip6h->saddr.in6_u.u6_addr32, saddr, 16);
  ip6h->saddr.in6_u.u6_addr32[0] = saddr[0];
  ip6h->saddr.in6_u.u6_addr32[1] = saddr[1];
  ip6h->saddr.in6_u.u6_addr32[2] = saddr[2];
  ip6h->saddr.in6_u.u6_addr32[3] = saddr[3];
  __builtin_memcpy(ip6h->daddr.in6_u.u6_addr32, daddr, 16);
}

__attribute__((__always_inline__)) static inline bool encap_gue(
    struct __sk_buff* skb,
    const volatile union kde_ip_address* src_ip,
    const union kde_ip_address* de_ip,
    __be16 sport,
    __u16 dport) {
  // TODO: support IPv4
  void* data = (void*)(long)skb->data;
  void* data_end = (void*)(long)skb->data_end;
  if ((data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr)) > data_end) {
    return false;
  }
  struct ipv6hdr* inner_ip6h = data + sizeof(struct ethhdr);
  __u8 inner_priority = inner_ip6h->priority;
  __u8 inner_flow_lbl[3] = {
      inner_ip6h->flow_lbl[0],
      inner_ip6h->flow_lbl[1],
      inner_ip6h->flow_lbl[2],
  };
  __u8 inner_hop_limit = inner_ip6h->hop_limit;

  /* when socket is abruptly closed with data pending in the send buffer,
   * generates RST but bpf_sock->src_port is cleared. try to read sport from
   * tcphdr. fallback on hashing as the last option. */
  if (sport == 0 && inner_ip6h->nexthdr == IPPROTO_TCP) {
    struct tcphdr* tcp = (void*)(inner_ip6h + 1);
    if (tcp + 1 > data_end) {
      return false;
    }
    sport = tcp->source;
  }
  if (sport == 0) {
    sport = gue_sport(de_ip->v6addr[0] | de_ip->v6addr[3]);
  }
  // safeguard supported encap port, preventing incorrect userspace config
  // if it is not a valid GUE port, override with GUE_DPORT as default
  if (!IS_VALID_GUE_DPORT(dport)) {
    dport = GUE_DPORT;
  }
  __u8 proto = IPPROTO_IPV6;
  __u64 flags = BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_ENCAP_L3_IPV6 |
      BPF_F_ADJ_ROOM_ENCAP_L4_UDP;
  int adjust_len = sizeof(struct ipv6hdr) + sizeof(struct udphdr);
  // new headers would be inserted after MAC but before old L3 header
  if (bpf_skb_adjust_room(skb, adjust_len, BPF_ADJ_ROOM_MAC, flags)) {
    return false;
  }
  data = (void*)(long)skb->data;
  data_end = (void*)(long)skb->data_end;
  if ((data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) +
       sizeof(struct udphdr)) > data_end) {
    return false;
  }
  struct ethhdr* ethh = data;
  ethh->h_proto = BE_ETH_P_IPV6;

  __u32 pkt_len = skb->len - sizeof(struct ethhdr) - sizeof(struct ipv6hdr);
  __u16 hdr_len = pkt_len > 0xFFFF ? 0 : pkt_len; // 0 if bigger than 16 bits
  struct ipv6hdr* ip6h = data + sizeof(struct ethhdr);
  struct udphdr* udph = (void*)ip6h + sizeof(struct ipv6hdr);
  create_udp_hdr(udph, sport, dport, hdr_len, GUE_CSUM);
  create_v6_hdr(
      ip6h,
      inner_priority,
      &inner_flow_lbl,
      src_ip->v6addr,
      de_ip->v6addr,
      hdr_len,
      IPPROTO_UDP,
      inner_hop_limit);
  return true;
}

static inline struct ipv6hdr* parse_ipv6_hdr(void* data, void* data_end) {
  struct ethhdr* eth = (struct ethhdr*)(data);
  if (eth + 1 > data_end) {
    return NULL;
  }

  struct ipv6hdr* hdr = (struct ipv6hdr*)(data + sizeof(struct ethhdr));
  return hdr;
}

/* BIG TCP on kernels < 7.0 inserts a jumbo HBH header between IPv6 and TCP
 * on skbs > 64KB. Drivers (TSO) and GSO strip it only from non-encapsulated
 * packets, so remove it before encap. Removed upstream in 7.0:
 * https://git.kernel.org/torvalds/c/741d069aa488
 * Runs before direct_encap() reads packet pointers, which adjust_room
 * invalidates. */
__attribute__((__always_inline__)) static inline bool remove_jumbo_hbh(
    struct __sk_buff* skb) {
  void* data = (void*)(long)skb->data;
  void* data_end = (void*)(long)skb->data_end;
  struct ethhdr* eth = data;
  struct ipv6hdr* ip6 = (void*)(eth + 1);
  struct kde_hop_jumbo_hdr* hbh = (void*)(ip6 + 1);
  if ((void*)(hbh + 1) > data_end || eth->h_proto != BE_ETH_P_IPV6 ||
      ip6->payload_len != 0 || ip6->nexthdr != IPPROTO_HOPOPTS ||
      hbh->nexthdr != IPPROTO_TCP || hbh->hdrlen != 0 ||
      hbh->tlv_type != IPV6_TLV_JUMBO) {
    return true;
  }
  if (bpf_skb_adjust_room(
          skb, -8, BPF_ADJ_ROOM_NET, BPF_F_ADJ_ROOM_FIXED_GSO)) {
    return false;
  }
  __u8 nexthdr = IPPROTO_TCP;
  return !bpf_skb_store_bytes(
      skb,
      sizeof(struct ethhdr) + offsetof(struct ipv6hdr, nexthdr),
      &nexthdr,
      sizeof(nexthdr),
      0);
}

static inline int direct_encap(
    struct __sk_buff* skb,
    __be16 sport,
    struct encap_sk_info* ei,
    // 64-bit, also at the callers: kernels < 5.14 lose its bounds check across
    // a 4-byte stack spill or a 32-to-64-bit copy, failing the stats array
    // access
    __u64 cpu_num) {
  if (!remove_jumbo_hbh(skb)) {
    KDE_TC_STAT_INC(encap_fail);
    return TC_ACT_SHOT;
  }

  void* data = (void*)(long)skb->data;
  void* data_end = (void*)(long)skb->data_end;
  __u64 encap_payload = skb->len;

  if ((data + sizeof(struct ethhdr)) > data_end) {
    return TC_ACT_UNSPEC;
  }

  struct ethhdr* ethh = data;
  if (ethh->h_proto != BE_ETH_P_IPV6) {
    // TODO: support IPv4
    return TC_ACT_UNSPEC;
  }

  struct ipv6hdr* hdr = parse_ipv6_hdr(data, data_end);
  if (!hdr || hdr + 1 > data_end) {
    KDE_TC_STAT_INC(error_parse_src);
    return TC_ACT_UNSPEC;
  }

  union kde_ip_address src_addr = {};
  memcpy(src_addr.v6addr, &hdr->saddr, 16);

  if (ei->nat_sport && hdr->nexthdr == IPPROTO_TCP) {
    struct tcphdr* tcphdr = (void*)(hdr + 1);
    if (tcphdr + 1 > data_end) {
      KDE_TC_STAT_INC(error_parse_src);
      return TC_ACT_UNSPEC;
    }
    __be16 old_sport = tcphdr->source;
    __be16 new_sport = ei->nat_sport;
    __u32 tcp_off = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
    if (bpf_l4_csum_replace(
            skb,
            tcp_off + offsetof(struct tcphdr, check),
            old_sport,
            new_sport,
            sizeof(new_sport))) {
      KDE_TC_STAT_INC(nat_replace_fail);
      /* UNSPEC would skip encap and fall back to the load balancer.
       * Better to drop and fail loudly */
      return TC_ACT_SHOT;
    }
    if (bpf_skb_store_bytes(
            skb,
            tcp_off + offsetof(struct tcphdr, source),
            &new_sport,
            sizeof(new_sport),
            0)) {
      KDE_TC_STAT_INC(nat_replace_fail);
      return TC_ACT_SHOT;
    }
  }

  __u16 dport = ei->encap_port;
  if (!encap_gue(skb, &src_addr, &ei->direct_ip, sport, dport)) {
    KDE_TC_STAT_INC(encap_fail);
    return TC_ACT_SHOT;
  }

  data = (void*)(long)skb->data;
  data_end = (void*)(long)skb->data_end;
  if (data + sizeof(struct ethhdr) > data_end) {
    KDE_TC_STAT_INC(encap_fail);
    return TC_ACT_SHOT;
  }

  KDE_TC_STAT_INC(encap_ok);
  KDE_TC_STAT_INC_VALUE(encap_bytes, skb->len);
  KDE_TC_STAT_INC_VALUE(encap_payload_bytes, encap_payload);

  // Count each connection once. The atomic test-and-set keeps the count exact
  // if the same socket encapsulates on multiple CPUs concurrently.
  if (__sync_val_compare_and_swap(&ei->encapped, 0, 1) == 0) {
    KDE_TC_STAT_INC(conns_encapped);
  }

  return TC_ACT_UNSPEC;
}
