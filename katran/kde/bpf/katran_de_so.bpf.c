#include <bpf/vmlinux/vmlinux.h>

#include <bpf/bpf_helpers.h>

#include <katran/kde/bpf/kde_shared_maps.h>
#include <katran/kde/bpf/kde_so_client.h>
#include <katran/kde/bpf/kde_so_server.h>
#include <katran/kde/bpf/kde_types.h>

char LICENSE[] SEC("license") = "GPL";

// Exported in the read-only data map for program versioning.
SEC(".rodata")
__attribute__((used))
const struct kde_bpf_version bpf_metadata_kde_bpf_version = {
    .version = KDE_PROG_VERSION};

const volatile int g_direct_encap_mode = DIRECT_ENCAP_MODE_CLIENT;

const volatile union kde_ip_address g_direct_ip = {};

const volatile struct kde_log_config g_kde_log_config = {};

struct kde_stats g_stats[MAX_CPUS];

SEC("sockops")
int katran_de_so(struct bpf_sock_ops* skops) {
  if (!skops) {
    return CG_OK;
  }
  __u32 cpu_num = bpf_get_smp_processor_id();
  if (g_direct_encap_mode == DIRECT_ENCAP_MODE_CLIENT) {
    return handle_client(skops, cpu_num);
  } else {
    return handle_server(skops, cpu_num);
  }
  return CG_OK;
}
