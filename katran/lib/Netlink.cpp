#include "Netlink.h"

#include <array>

#include <libmnl/libmnl.h>
#include <cstring>

extern "C" {
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/rtnetlink.h>
#include <linux/tc_act/tc_gact.h>
}

// from linux/pkt_cls.h bpf specific constants
/* BPF classifier */
#ifndef TCA_BPF_FLAG_ACT_DIRECT
#define TCA_BPF_FLAG_ACT_DIRECT (1 << 0)
#endif

namespace {
// netlink/tc magic constants (from iproute2/tc source code)
std::array<const char, 4> kBpfKind = {"bpf"};
std::array<const char, 5> kTcActKind = {"gact"};
std::array<const char, 7> kClsActKind = {"clsact"};
constexpr unsigned TCA_BPF_PRIO_1 = 1;
} // namespace

namespace katran {

NetlinkMessage::NetlinkMessage() : buf_(MNL_SOCKET_BUFFER_SIZE) {}

NetlinkMessage NetlinkMessage::TC(
    unsigned seq,
    int cmd,
    unsigned flags,
    uint32_t priority,
    int prog_fd,
    unsigned ifindex,
    const std::string& bpf_name,
    int direction) {
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

  NetlinkMessage ret;
  unsigned char* buf = ret.buf_.data();

  struct nlmsghdr* nlh;
  struct tcmsg* tc;
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

  ret.buf_.resize(nlh->nlmsg_len);
  return ret;
}

NetlinkMessage NetlinkMessage::QD(unsigned ifindex) {
  NetlinkMessage ret;
  unsigned char* buf = ret.buf_.data();

  struct nlmsghdr* nlh;
  struct tcmsg* tc;

  // Construct netlink message header
  nlh = mnl_nlmsg_put_header(buf);
  nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE;
  nlh->nlmsg_type = RTM_NEWQDISC;

  // Construct tc message header
  tc = reinterpret_cast<struct tcmsg*>(
      mnl_nlmsg_put_extra_header(nlh, sizeof(struct tcmsg)));
  tc->tcm_family = AF_UNSPEC;
  tc->tcm_parent = TC_H_CLSACT;
  tc->tcm_handle = TC_H_MAKE(TC_H_CLSACT, 0);
  tc->tcm_ifindex = ifindex;

  // Additional nested attribues
  mnl_attr_put(nlh, TCA_KIND, kClsActKind.size(), kClsActKind.data());

  ret.buf_.resize(nlh->nlmsg_len);
  return ret;
}

NetlinkMessage NetlinkMessage::XDP(
    unsigned seq,
    int prog_fd,
    unsigned ifindex,
    uint32_t flags) {
  NetlinkMessage ret;
  unsigned char* buf = ret.buf_.data();

  struct nlmsghdr* nlh;
  struct ifinfomsg* ifinfo;

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

  ret.buf_.resize(nlh->nlmsg_len);
  return ret;
}

unsigned NetlinkMessage::seq() const {
  const struct nlmsghdr* hdr = reinterpret_cast<const struct nlmsghdr*>(data());
  return hdr->nlmsg_seq;
}
} // namespace katran
