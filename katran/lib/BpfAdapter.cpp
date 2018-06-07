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

#include "BpfAdapter.h"

#include <folly/ScopeGuard.h>
#include <glog/logging.h>
#include <libmnl/libmnl.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <stdexcept>

extern "C" {
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/netlink.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <linux/tc_act/tc_gact.h>
#include <net/if.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>

#include "linux_includes/libbpf.h"
}

namespace {
// netlink/tc magic constants (from iproute2/tc source code)
constexpr short MAX_MSG_SIZE = 4096;
constexpr unsigned TCA_BPF_PRIO_1 = 1;
constexpr int TC_HANDLE = 0x1;
constexpr int TC_CLASS_ID = 1;
constexpr int TC_ACTION_OK = TC_ACT_OK;
std::array<const char, 4> kBpfKind = {"bpf"};
std::array<const char, 5> kTcActKind = {"gact"};
constexpr int kMaxPathLen = 255;

// from linux/pkt_cls.h bpf specific constants
/* BPF classifier */
#ifndef TCA_BPF_FLAG_ACT_DIRECT
#define TCA_BPF_FLAG_ACT_DIRECT (1 << 0)
#endif
enum {
  TCA_BPF_UNSPEC,
  TCA_BPF_ACT,
  TCA_BPF_POLICE,
  TCA_BPF_CLASSID,
  TCA_BPF_OPS_LEN,
  TCA_BPF_OPS,
  TCA_BPF_FD,
  TCA_BPF_NAME,
  TCA_BPF_FLAGS,
  __TCA_BPF_MAX,
};
} // namespace

#ifndef IFLA_XDP
#define IFLA_XDP (43)
#endif
#ifndef IFLA_XDP_FD
#define IFLA_XDP_FD (1)
#endif
#ifndef IFLA_XDP_FLAGS
#define IFLA_XDP_FLAGS (3)
#endif

namespace {
constexpr int kNoMap = -1;
}

namespace katran {

BpfAdapter::BpfAdapter(bool set_limits) {
  if (set_limits) {
    struct rlimit lck_mem = {};
    lck_mem.rlim_cur = RLIM_INFINITY;
    lck_mem.rlim_max = RLIM_INFINITY;
    if (setrlimit(RLIMIT_MEMLOCK, &lck_mem)) {
      LOG(ERROR) << "Can't change limit for locked memory";
      throw std::runtime_error("error while setting limit for locked memory");
    }
  }
}

int BpfAdapter::loadBpfProg(
    const std::string& bpf_prog,
    const bpf_prog_type type) {
  return loader_.loadBpfFile(bpf_prog, type);
}

int BpfAdapter::getMapFdByName(const std::string& name) {
  return loader_.getMapFdByName(name);
}

int BpfAdapter::createBpfMap(
    unsigned int type,
    unsigned int key_size,
    unsigned int value_size,
    unsigned int max_entries,
    unsigned int map_flags,
    int numa_node) {
  return createNamedBpfMap(
      "", type, key_size, value_size, max_entries, map_flags, numa_node);
}

int BpfAdapter::createNamedBpfMap(
    const std::string& name,
    unsigned int type,
    unsigned int key_size,
    unsigned int value_size,
    unsigned int max_entries,
    unsigned int map_flags,
    int numa_node) {
  const char* name_ptr = !name.empty() ? name.c_str() : nullptr;

  return ebpf_create_map_node(
      static_cast<enum bpf_map_type>(type),
      name_ptr,
      key_size,
      value_size,
      max_entries,
      map_flags,
      numa_node);
}

int BpfAdapter::updateInnerMapsArray(int pos, int map_fd) {
  return loader_.updateInnerMapsArray(pos, map_fd);
}

int BpfAdapter::getProgFdByName(const std::string& name) {
  return loader_.getProgFdByName(name);
}

int BpfAdapter::bpfUpdateMap(
    int map_fd,
    void* key,
    void* value,
    unsigned long long flags) {
  auto bpfError = ebpf_update_elem(map_fd, key, value, flags);
  if (bpfError) {
    VLOG(4) << "Error while updating value in map: " << std::strerror(errno);
  }
  return bpfError;
}

int BpfAdapter::bpfMapLookupElement(int map_fd, void* key, void* value) {
  auto bpfError = ebpf_lookup_elem(map_fd, key, value);
  if (bpfError) {
    VLOG(4) << "Error while geting value from map: " << std::strerror(errno);
  }
  return bpfError;
}

int BpfAdapter::bpfMapDeleteElement(int map_fd, void* key) {
  auto bpfError = ebpf_delete_elem(map_fd, key);
  if (bpfError) {
    VLOG(4) << "Error while deleting key from map: " << std::strerror(errno);
  }
  return bpfError;
}

int BpfAdapter::bpfMapGetNextKey(int map_fd, void* key, void* next_key) {
  auto bpfError = ebpf_get_next_key(map_fd, key, next_key);
  if (bpfError) {
    VLOG(4) << "Error getting next key from map: " << std::strerror(errno);
  }
  return bpfError;
}

int BpfAdapter::pinBpfObject(int fd, const std::string& path) {
  return ebpf_obj_pin(fd, path.c_str());
}

int BpfAdapter::getPinnedBpfObject(const std::string& path) {
  return ebpf_obj_get(path.c_str());
}

int BpfAdapter::getInterfaceIndex(const std::string& interface_name) {
  int ifindex = if_nametoindex(interface_name.c_str());
  if (!ifindex) {
    VLOG(1) << "can't resolve ifindex for interface " << interface_name;
    return 0;
  }
  return ifindex;
}

int BpfAdapter::attachBpfProgToTc(
    const int prog_fd,
    const std::string& interface_name,
    const int direction,
    const std::string& bpf_name,
    const uint32_t priority) {
  unsigned int ifindex = if_nametoindex(interface_name.c_str());
  if (!ifindex) {
    VLOG(1) << "can't resolve ifindex for interface: " << interface_name;
    return 1;
  }
  return genericAttachBpfProgToTc(
      prog_fd, ifindex, bpf_name, priority, direction);
}

int BpfAdapter::attachXdpProg(
    const int prog_fd,
    const std::string& interface_name) {
  unsigned int ifindex = if_nametoindex(interface_name.c_str());
  if (!ifindex) {
    VLOG(1) << "can't resolve ifindex for interface: " << interface_name;
    return 1;
  }
  return modifyXdpProg(prog_fd, ifindex);
}

int BpfAdapter::detachXdpProg(const std::string& interface_name) {
  unsigned int ifindex = if_nametoindex(interface_name.c_str());
  if (!ifindex) {
    VLOG(1) << "can't resolve ifindex for interface: " << interface_name;
    return 1;
  }
  return modifyXdpProg(-1, ifindex);
}

int BpfAdapter::detachXdpProg(const int ifindex) {
  return modifyXdpProg(-1, ifindex);
}

int BpfAdapter::addTcBpfFilter(
    const int prog_fd,
    const unsigned int ifindex,
    const std::string& bpf_name,
    const uint32_t priority,
    const int direction) {
  return genericAttachBpfProgToTc(
      prog_fd, ifindex, bpf_name, priority, direction);
}

int BpfAdapter::replaceTcBpfFilter(
    const int prog_fd,
    const unsigned int ifindex,
    const std::string& bpf_name,
    const uint32_t priority,
    const int direction) {
  int cmd = RTM_NEWTFILTER;
  unsigned int flags = NLM_F_CREATE;
  return modifyTcBpfFilter(
      cmd, flags, priority, prog_fd, ifindex, bpf_name, direction);
}

int BpfAdapter::deleteTcBpfFilter(
    const int prog_fd,
    const unsigned int ifindex,
    const std::string& bpf_name,
    const uint32_t priority,
    const int direction) {
  int cmd = RTM_DELTFILTER;
  unsigned int flags = 0;
  return modifyTcBpfFilter(
      cmd, flags, priority, prog_fd, ifindex, bpf_name, direction);
}

int BpfAdapter::genericAttachBpfProgToTc(
    const int prog_fd,
    const unsigned int ifindex,
    const std::string& bpf_name,
    const uint32_t priority,
    const int direction) {
  int cmd = RTM_NEWTFILTER;
  unsigned int flags = NLM_F_EXCL | NLM_F_CREATE;

  auto rc = modifyTcBpfFilter(
      cmd, flags, priority, prog_fd, ifindex, bpf_name, direction);
  return rc;
}

int BpfAdapter::testXdpProg(
    const int prog_fd,
    const int repeat,
    void* data,
    uint32_t data_size,
    void* data_out,
    uint32_t* size_out,
    uint32_t* retval,
    uint32_t* duration) {
  return ebpf_prog_test_run(
      prog_fd, repeat, data, data_size, data_out, size_out, retval, duration);
}

int BpfAdapter::modifyXdpProg(
    const int prog_fd,
    const unsigned int ifindex,
    const uint32_t flags) {
  //
  char buf[MNL_SOCKET_BUFFER_SIZE];
  struct nlmsghdr* nlh;
  struct ifinfomsg* ifinfo;
  unsigned int seq = static_cast<unsigned int>(std::time(nullptr));

  // Construct netlink message header
  nlh = mnl_nlmsg_put_header(buf);
  nlh->nlmsg_type = RTM_SETLINK;
  nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  nlh->nlmsg_seq = seq;

  // Construct ifinfo message header
  ifinfo = reinterpret_cast<struct ifinfomsg*>(
      mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg)));
  ifinfo->ifi_family = AF_UNSPEC;
  ifinfo->ifi_index = ifindex;

  // Additional nested attribues
  {
    struct nlattr* xdp_atr = mnl_attr_nest_start(nlh, IFLA_XDP);
    mnl_attr_put_u32(nlh, IFLA_XDP_FD, prog_fd);
    if (flags > 0) {
      mnl_attr_put_u32(nlh, IFLA_XDP_FLAGS, flags);
    }
    mnl_attr_nest_end(nlh, xdp_atr);
  }

  // Perform netlink communication
  struct mnl_socket* nl = mnl_socket_open(NETLINK_ROUTE);
  if (!nl) {
    PLOG(ERROR) << "Unable to open netlink socket";
    return -1;
  }
  SCOPE_EXIT {
    mnl_socket_close(nl);
  };

  if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
    PLOG(ERROR) << "Unable to bind netlink socket";
    return -1;
  }

  unsigned int portId = mnl_socket_get_portid(nl);

  if (VLOG_IS_ON(4)) {
    // Dump netlink message for debugging
    mnl_nlmsg_fprintf(stderr, nlh, nlh->nlmsg_len, sizeof(struct ifinfomsg));
  }

  if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
    PLOG(ERROR) << "Error sending netlink message";
    return -1;
  }

  int ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
  while (ret > 0) {
    ret = mnl_cb_run(buf, ret, seq, portId, nullptr, nullptr);
    if (ret <= MNL_CB_STOP) {
      break;
    }
    ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
  }
  if (ret < 0) {
    PLOG(ERROR) << "Error receiving netlink message";
  }

  return ret;
}

int BpfAdapter::modifyTcBpfFilter(
    /**
      format of netlink msg:
      +-------------------------------+
      |type                           |
      +-------------------------------+
      |flags                          |
      +-------------------------------+
      |seq                            |
      +-------------------------------+
      |##### TC's header #####        |
      +-------------------------------+
      |family                         |
      +-------------------------------+
      |ifindex                        |
      +-------------------------------+
      |parent                         |
      +-------------------------------+
      |tcm_info                       |
      +-------------------------------+
      |TCA_KIND                       |
      +-------------------------------+
      |TCA_options (nested)           |
      +-------------------------------+
      |bpf prog fd                    |
      +-------------------------------+
      |bpf flags                      |
      +-------------------------------+
      |bpf name                       |
      +-------------------------------+
      |TCA bpf act (nested)           |
      +-------------------------------+
      |TCA bpf prio (nested)          |
      +-------------------------------+
      |TCA act  kind                  |
      +-------------------------------+
      |TCA act options (nested)       |
      +-------------------------------+
      |TCA gact params                |
      +-------------------------------+
      |end of TCA act options         |
      +-------------------------------+
      |end of TCA bpf prio            |
      +-------------------------------+
      |end of TCA bpf act             |
      +-------------------------------+
      |end of TCA options             |
      +-------------------------------+

      netlink's header:

      1) type: depends of command, add/delete/modify filter (actual constanst in
         helpers above)
      2) flags: depends of the type; could be create/ create + exclusive / 0 (in
         case of delitation)
      3) seq - seq number for this message, we are going to use cur time in sec

      tc related headers and fields:
      1) family: either 0 for deletation or ETH_P_ALL if we are adding new
      filter 2) ifindex: index of interface where we are going to attach our
      prog. 3) parent: for bpf this field indicates the direction of the filter.
         either ingress or egress.
      4) tcm_info: for tc's filter this field combines protocol and priority
         (rfc3549 3.1.3)
      5) TCA_KIND: for bpf it's "bpf"
      bpf's specific options:
      1) bpf_prog_fd: file descriptor of already loaded bpf program
      2) bpf_flags: bpf related flags; for our use case use are using
         "direct action" (for imediate return after BPF run)
      3) bpf_name: name of bpf prog (to identify it, e.g. in tc show output), no
         special meaning behind this.
      4) act_kind: for bpf's related filter it's fixed to "gact"
      5) gact params: we only specify default action as TC_ACT_OK (we are going
         to hit this only if bpf prog exits w/ TC_ACT_PIPE and there is not
      filter after it)

    */

    const int cmd,
    const unsigned int flags,
    const uint32_t priority,
    const int prog_fd,
    const unsigned int ifindex,
    const std::string& bpf_name,
    const int direction)
// TODO: T30063437 fix null-pointer-use undefined behavior
#if defined(__has_feature)
#if __has_feature(__address_sanitizer__)
    __attribute__((__no_sanitize__("null")))
#endif
#endif
{
  char buf[MNL_SOCKET_BUFFER_SIZE];
  struct nlmsghdr* nlh;
  struct tcmsg* tc;
  unsigned int seq = static_cast<unsigned int>(std::time(nullptr));
  uint32_t protocol = 0;
  unsigned int bpfFlags = TCA_BPF_FLAG_ACT_DIRECT;

  // Construct netlink message header
  nlh = mnl_nlmsg_put_header(buf);
  nlh->nlmsg_type = cmd;
  nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags;
  nlh->nlmsg_seq = seq;

  // Construct tc message header
  tc = reinterpret_cast<struct tcmsg*>(
      mnl_nlmsg_put_extra_header(nlh, sizeof(struct tcmsg)));
  tc->tcm_family = AF_UNSPEC;
  tc->tcm_ifindex = ifindex;
  tc->tcm_parent = direction;

  if (cmd == RTM_NEWTFILTER && flags & NLM_F_CREATE) {
    protocol = htons(ETH_P_ALL);
  }
  tc->tcm_info = TC_H_MAKE(priority << 16, protocol);

  // Additional nested attribues
  mnl_attr_put(nlh, TCA_KIND, kBpfKind.size(), kBpfKind.data());
  {
    struct nlattr* options = mnl_attr_nest_start(nlh, TCA_OPTIONS);
    mnl_attr_put_u32(nlh, ::TCA_BPF_FD, prog_fd);
    mnl_attr_put_u32(nlh, ::TCA_BPF_FLAGS, bpfFlags);
    mnl_attr_put(nlh, ::TCA_BPF_NAME, bpf_name.size() + 1, bpf_name.c_str());
    {
      struct nlattr* act = mnl_attr_nest_start(nlh, ::TCA_BPF_ACT);
      {
        struct nlattr* prio = mnl_attr_nest_start(nlh, TCA_BPF_PRIO_1);
        mnl_attr_put(nlh, ::TCA_ACT_KIND, kTcActKind.size(), kTcActKind.data());
        {
          struct nlattr* actOptions =
              mnl_attr_nest_start(nlh, ::TCA_ACT_OPTIONS);
          struct tc_gact gactParm;
          memset(&gactParm, 0, sizeof(gactParm));
          gactParm.action = TC_ACT_OK;
          mnl_attr_put(nlh, ::TCA_GACT_PARMS, sizeof(gactParm), &gactParm);
          mnl_attr_nest_end(nlh, actOptions);
        }
        mnl_attr_nest_end(nlh, prio);
      }
      mnl_attr_nest_end(nlh, act);
    }
    mnl_attr_nest_end(nlh, options);
  }

  // Perform netlink communication
  struct mnl_socket* nl = mnl_socket_open(NETLINK_ROUTE);
  if (!nl) {
    PLOG(ERROR) << "Unable to open netlink socket";
    return -1;
  }
  SCOPE_EXIT {
    mnl_socket_close(nl);
  };

  if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
    PLOG(ERROR) << "Unable to bind netlink socket";
    return -1;
  }

  unsigned int portId = mnl_socket_get_portid(nl);

  if (VLOG_IS_ON(4)) {
    // Dump netlink message for debugging
    mnl_nlmsg_fprintf(stderr, nlh, nlh->nlmsg_len, sizeof(struct tcmsg));
  }

  if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
    PLOG(ERROR) << "Error sending netlink message";
    return -1;
  }

  int ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
  while (ret > 0) {
    ret = mnl_cb_run(buf, ret, seq, portId, nullptr, nullptr);
    if (ret <= MNL_CB_STOP) {
      break;
    }
    ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
  }
  if (ret < 0) {
    PLOG(ERROR) << "Error receiving netlink message";
  }

  return ret;
}

int BpfAdapter::getDirFd(const std::string& path) {
  return ::open(path.c_str(), O_DIRECTORY, O_RDONLY);
}

int BpfAdapter::attachCgroupProg(
    int prog_fd,
    const std::string& cgroup,
    enum bpf_attach_type type,
    unsigned int flags) {
  auto target_fd = getDirFd(cgroup);
  if (target_fd < 0) {
    return -1;
  }
  SCOPE_EXIT {
    ::close(target_fd);
  };
  return ebpf_prog_attach(prog_fd, target_fd, type, flags);
}

int BpfAdapter::detachCgroupProg(
    const std::string& cgroup,
    enum bpf_attach_type type) {
  auto target_fd = getDirFd(cgroup);
  if (target_fd < 0) {
    return -1;
  }
  SCOPE_EXIT {
    ::close(target_fd);
  };
  return ebpf_prog_detach(target_fd, type);
}

int BpfAdapter::detachCgroupProg(
    int prog_fd,
    const std::string& cgroup,
    enum bpf_attach_type type) {
  auto target_fd = getDirFd(cgroup);
  if (target_fd < 0) {
    return -1;
  }
  SCOPE_EXIT {
    ::close(target_fd);
  };
  return ebpf_prog_detach2(prog_fd, target_fd, type);
}

} // namespace katran
