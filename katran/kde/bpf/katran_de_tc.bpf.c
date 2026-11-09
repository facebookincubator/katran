// Packet and __sk_buff layouts are fixed; CO-RE relocations on __sk_buff
// fields break the verifier's constant-offset ctx access check.
#define BPF_NO_PRESERVE_ACCESS_INDEX
#include <bpf/vmlinux/vmlinux.h>

#include <bpf/bpf_helpers.h>

#include <katran/kde/bpf/kde_encap.h>
#include <katran/kde/bpf/kde_shared_maps.h>
#include <katran/kde/bpf/kde_types.h>
#include <katran/kde/bpf/kde_utils.h>

char LICENSE[] SEC("license") = "GPL";

// from linux/pkt_cls.h
#define TC_ACT_UNSPEC (-1)
#define TC_ACT_SHOT 2

#define REDIRECT_EGRESS 0

SEC(".rodata")
__attribute__((used))
const struct kde_bpf_version bpf_metadata_kde_bpf_version = {
    .version = KDE_PROG_VERSION};

struct kde_tc_stats g_tc_stats[MAX_CPUS];

/* host mode: one instance serves all containers on the host and tc runs on
   the host NIC egress. By then the host has forwarded the packet and
   cleared skb->sk, so the socket's storage is unreachable from tc. Store
   the direct IP in a map keyed by the connection tuple instead. */
const volatile __u8 g_kde_client_host_mode = 0;

SEC("tc")
int katran_de_tc(struct __sk_buff* skb) {
  __u64 cpu_num = bpf_get_smp_processor_id();
  struct encap_sk_info* ei;
  __be16 sport;

  if (!skb) {
    return TC_ACT_UNSPEC;
  }

  if (g_kde_client_host_mode) {
    /* parse headers to create tuple */
    void* data = (void*)(long)skb->data;
    void* data_end = (void*)(long)skb->data_end;
    struct ethhdr* eth = (void*)data;
    if (eth + 1 > data_end || eth->h_proto != BE_ETH_P_IPV6) {
      return TC_ACT_UNSPEC;
    }
    struct ipv6hdr* ip6 = (void*)(eth + 1);
    if (ip6 + 1 > data_end || ip6->nexthdr != IPPROTO_TCP) {
      return TC_ACT_UNSPEC;
    }
    struct tcphdr* tcp = (void*)(ip6 + 1);
    if (tcp + 1 > data_end) {
      return TC_ACT_UNSPEC;
    }
    struct tuple key = {};
    memcpy(key.local_ip6, &ip6->saddr, 16);
    memcpy(key.remote_ip6, &ip6->daddr, 16);
    key.local_port = tcp->source;
    key.remote_port = tcp->dest;
    ei = bpf_map_lookup_elem(&katran_de_tuple_store, &key);
    if (!ei) {
      KDE_TC_STAT_INC(no_tuple_store);
      return TC_ACT_UNSPEC;
    }
    KDE_TC_STAT_INC(in_tuple_store);
    sport = tcp->source;
  }
  // container mode
  else {
    struct bpf_sock* sk = skb->sk;
    if (!sk) {
      return TC_ACT_UNSPEC;
    }
    if (sk->state == TCP_LISTEN) {
      return TC_ACT_UNSPEC;
    }
    struct bpf_sock* bpf_sk = bpf_sk_fullsock(sk);
    if (!bpf_sk) {
      return TC_ACT_UNSPEC;
    }
    // TODO: skip non TCP protos. stats should only consider TCP
    ei = bpf_sk_storage_get(&katran_de_sk_store, bpf_sk, NULL, NO_FLAGS);
    if (!ei) {
      KDE_TC_STAT_INC(no_sk_store);
      return TC_ACT_UNSPEC;
    }
    KDE_TC_STAT_INC(in_sk_store);
    sport = bpf_htons(bpf_sk->src_port);
  }

  return direct_encap(skb, sport, ei, cpu_num);
}
