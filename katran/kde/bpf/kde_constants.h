#pragma once

#include <bpf/bpf_helpers.h>
#ifdef KATRAN_CMAKE_BUILD
#include "vmlinux.h"
#else
#include <bpf/vmlinux/vmlinux.h>
#endif
#include <katran/kde/bpf/kde_types.h>
#include <linux/errno.h>

#define TCP_SAVE_SYN 27
#define MAX_CPUS 512

#define TCPHDR_SYN 0x02
#define TCPHDR_ACK 0x10
#define TCPHDR_SYNACK (TCPHDR_SYN | TCPHDR_ACK)
#define AF_INET6 10
#define ETH_P_IPV6 0x86DD

#define CG_OK 1
#define CG_ERR 0

#define NO_FLAGS 0
