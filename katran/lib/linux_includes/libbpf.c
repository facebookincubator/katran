/* eBPF mini library */
#include <stdio.h>
#include <linux/unistd.h>
#include <unistd.h>
#include <string.h>
#include <linux/netlink.h>
#include "bpf.h"
#include <errno.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include "libbpf.h"

#define min(x, y) ((x) < (y) ? (x) : (y))

static __u64 ptr_to_u64(const void *ptr)
{
  return (__u64) (unsigned long) ptr;
}

static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr,
        unsigned int size)
{
  return syscall(__NR_bpf, cmd, attr, size);
}

int ebpf_create_map_node(enum bpf_map_type map_type, const char *name,
                        int key_size, int value_size, int max_entries,
                        __u32 map_flags, int node)
{
  union bpf_attr attr;

  memset(&attr, '\0', sizeof(attr));

  attr.map_type = map_type;
  attr.key_size = key_size;
  attr.value_size = value_size;
  attr.max_entries = max_entries;
  attr.map_flags = map_flags;
  if (name) {
    memcpy(attr.map_name, name, min(strlen(name), BPF_OBJ_NAME_LEN - 1));
  }

  if (node >= 0) {
    attr.map_flags |= BPF_F_NUMA_NODE;
    attr.numa_node = node;
  }

  return sys_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}

int ebpf_create_map_name(enum bpf_map_type map_type, const char *name,
                         int key_size, int value_size, int max_entries,
                         __u32 map_flags)
{
  return ebpf_create_map_node(map_type, name, key_size, value_size,
                              max_entries, map_flags, -1);
}


int ebpf_create_map(enum bpf_map_type map_type, int key_size, int value_size,
                    int max_entries, __u32 map_flags)
{
  return ebpf_create_map_node(map_type, NULL, key_size, value_size,
                              max_entries, map_flags, -1);
}

int ebpf_create_map_in_map_node(enum bpf_map_type map_type, const char *name,
                                int key_size, int inner_map_fd, int max_entries,
                                __u32 map_flags, int node)
{
  __u32 name_len = name ? strlen(name) : 0;
  union bpf_attr attr;

  memset(&attr, '\0', sizeof(attr));

  attr.map_type = map_type;
  attr.key_size = key_size;
  attr.value_size = 4;
  attr.inner_map_fd = inner_map_fd;
  attr.max_entries = max_entries;
  attr.map_flags = map_flags;
  memcpy(attr.map_name, name, min(name_len, BPF_OBJ_NAME_LEN - 1));

  if (node >= 0) {
    attr.map_flags |= BPF_F_NUMA_NODE;
    attr.numa_node = node;
  }

  return sys_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}



int ebpf_create_map_in_map(enum bpf_map_type map_type, int key_size,
        int inner_map_fd, int max_entries, __u32 map_flags)
{
  return ebpf_create_map_in_map_node(map_type, NULL, key_size,
                                     inner_map_fd, max_entries, map_flags, -1);
}

int ebpf_update_elem(int fd, void *key, void *value, unsigned long long flags)
{
  union bpf_attr attr;

  bzero(&attr, sizeof(attr));
  attr.map_fd = fd;
  attr.key = ptr_to_u64(key);
  attr.value = ptr_to_u64(value);
  attr.flags = flags;

  return sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

int ebpf_lookup_elem(int fd, void *key, void *value)
{
  union bpf_attr attr;

  bzero(&attr, sizeof(attr));
  attr.map_fd = fd;
  attr.key = ptr_to_u64(key);
  attr.value = ptr_to_u64(value);

  return sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

int ebpf_delete_elem(int fd, void *key)
{
  union bpf_attr attr;

  bzero(&attr, sizeof(attr));
  attr.map_fd = fd;
  attr.key = ptr_to_u64(key);

  return sys_bpf(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}

int ebpf_get_next_key(int fd, void *key, void *next_key)
{
  union bpf_attr attr;

  bzero(&attr, sizeof(attr));
  attr.map_fd = fd;
  attr.key = ptr_to_u64(key);
  attr.next_key = ptr_to_u64(next_key);

  return sys_bpf(BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
}

#define ROUND_UP(x, n) (((x) + (n) - 1u) & ~((n) - 1u))

int ebpf_prog_load_name(enum bpf_prog_type prog_type, const char *name,
                        const struct bpf_insn *insns, int prog_len,
                        const char *license, __u32 kern_version,
                        char *buf, int buf_size)
{
  int fd;
  union bpf_attr attr;

  bzero(&attr, sizeof(attr));
  attr.prog_type = prog_type;
  attr.insns = ptr_to_u64(insns);
  attr.insn_cnt = prog_len / sizeof(struct bpf_insn),
  attr.license = ptr_to_u64(license);
  attr.log_buf = ptr_to_u64(NULL);
  attr.log_size = 0;
  attr.log_level = 0;
  attr.kern_version = kern_version;
  if (name) {
    memcpy(attr.prog_name, name, min(strlen(name), BPF_OBJ_NAME_LEN - 1));
  }

  fd = sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
  if (fd >= 0 || !buf || !buf_size)
    return fd;

  /* Try again with log */
  attr.log_buf = ptr_to_u64(buf);
  attr.log_size = buf_size;
  attr.log_level = 1;
  return sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}


int ebpf_prog_load(enum bpf_prog_type prog_type,
                   const struct bpf_insn *insns, int prog_len,
                   const char *license, __u32 kern_version,
                   char *buf, int buf_size)
{
  return ebpf_prog_load_name(prog_type, NULL, insns, prog_len, license,
                               kern_version, buf, buf_size);
}

int ebpf_obj_pin(int fd, const char *pathname)
{
  union bpf_attr attr;

  bzero(&attr, sizeof(attr));
  attr.pathname = ptr_to_u64((void *)pathname);
  attr.bpf_fd = fd;

  return sys_bpf(BPF_OBJ_PIN, &attr, sizeof(attr));
}

int ebpf_obj_get(const char *pathname)
{
  union bpf_attr attr;

  bzero(&attr, sizeof(attr));
  attr.pathname = ptr_to_u64((void *)pathname);

  return sys_bpf(BPF_OBJ_GET, &attr, sizeof(attr));
}

int ebpf_prog_attach(int prog_fd, int target_fd, enum bpf_attach_type type,
                     unsigned int flags)
{
  union bpf_attr attr;

  bzero(&attr, sizeof(attr));
  attr.target_fd     = target_fd;
  attr.attach_bpf_fd = prog_fd;
  attr.attach_type   = type;
  attr.attach_flags  = flags;

  return sys_bpf(BPF_PROG_ATTACH, &attr, sizeof(attr));
}

int ebpf_prog_detach(int target_fd, enum bpf_attach_type type)
{
  union bpf_attr attr;

  bzero(&attr, sizeof(attr));
  attr.target_fd   = target_fd;
  attr.attach_type = type;

  return sys_bpf(BPF_PROG_DETACH, &attr, sizeof(attr));
}

int ebpf_prog_detach2(int prog_fd, int target_fd, enum bpf_attach_type type)
{
  union bpf_attr attr;

  bzero(&attr, sizeof(attr));
  attr.target_fd   = target_fd;
  attr.attach_bpf_fd = prog_fd;
  attr.attach_type = type;

  return sys_bpf(BPF_PROG_DETACH, &attr, sizeof(attr));
}

int ebpf_prog_test_run(int prog_fd, int repeat, void *data, __u32 size,
           void *data_out, __u32 *size_out, __u32 *retval,
           __u32 *duration)
{
  union bpf_attr attr;
  int ret;

  bzero(&attr, sizeof(attr));
  attr.test.prog_fd = prog_fd;
  attr.test.data_in = ptr_to_u64(data);
  attr.test.data_out = ptr_to_u64(data_out);
  attr.test.data_size_in = size;
  attr.test.repeat = repeat;

  ret = sys_bpf(BPF_PROG_TEST_RUN, &attr, sizeof(attr));
  if (size_out)
    *size_out = attr.test.data_size_out;
  if (retval)
    *retval = attr.test.retval;
  if (duration)
    *duration = attr.test.duration;
  return ret;
}

int ebpf_perf_event_open(struct perf_event_attr *attr, int pid, int cpu,
        int group_fd, unsigned long flags)
{
  return syscall(__NR_perf_event_open, attr, pid, cpu,
           group_fd, flags);
}
