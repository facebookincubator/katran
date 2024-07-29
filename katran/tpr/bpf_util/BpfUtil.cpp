// Copyright (c) Meta Platforms, Inc. and affiliates.

#include <katran/tpr/bpf_util/BpfUtil.h>

#include <fmt/core.h>
#include <fmt/format.h>
#include <folly/ScopeGuard.h>
#include <folly/portability/SysResource.h>
#include <folly/portability/Unistd.h>

#include <errno.h>
#include <glog/logging.h>

extern "C" {
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
}

// starting kernel 5.11 setting rlimit_memlock is no longer necessary
// https://lore.kernel.org/bpf/20211214195904.1785155-2-andrii@kernel.org/
DEFINE_bool(
    tpr_set_rlimit_memlock,
    false,
    "Whether we have to set rlimit_memlock in tpr bpf adapter.");

namespace katran_tpr::BpfUtil {

#if False
static int libbpf_print_fn(
    enum libbpf_print_level level,
    const char* format,
    va_list args) {
  return vfprintf(stderr, format, args);
}
#endif

SystemMaybe<folly::Unit> init() noexcept {
#if False // Enable to get libbpf internal logs
  libbpf_set_print(libbpf_print_fn);
#endif

  VLOG(1) << "Enabled libbpf strict mode";
  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

  return FLAGS_tpr_set_rlimit_memlock ? setRLimit() : noSystemError();
}

SystemMaybe<folly::Unit> setRLimit() noexcept {
  struct rlimit lck_mem = {};
  lck_mem.rlim_cur = RLIM_INFINITY;
  lck_mem.rlim_max = RLIM_INFINITY;
  if (setrlimit(RLIMIT_MEMLOCK, &lck_mem)) {
    int savedErrno = errno;
    return SYSTEM_ERROR(
        savedErrno,
        "Error while setting limit for locked memory, error:",
        folly::errnoStr(savedErrno));
  }
  return noSystemError();
}

int getDirFd(const std::string& path) noexcept {
  return ::open(path.c_str(), O_DIRECTORY, O_RDONLY);
}

SystemMaybe<folly::Unit> attachCgroupProg(
    int progFd,
    const std::string& cgroup,
    unsigned int flags) noexcept {
  auto targetFd = getDirFd(cgroup);
  if (targetFd < 0) {
    return SYSTEM_ERROR(
        EINVAL, fmt::format("Invalid target cgroup dir: {}", cgroup));
  }
  SCOPE_EXIT {
    ::close(targetFd);
  };
  if (bpf_prog_attach(progFd, targetFd, BPF_CGROUP_SOCK_OPS, flags)) {
    int savedErrno = errno;
    return SYSTEM_ERROR(
        savedErrno,
        fmt::format(
            "Error while attaching bpf prog fd: {} to cgroup: {}, error {} ",
            progFd,
            cgroup,
            folly::errnoStr(savedErrno)));
  }
  LOG(INFO) << "Successfully attached bpf prog at cgroup: " << cgroup;
  return noSystemError();
}

SystemMaybe<folly::Unit> detachCgroupProg(
    int progFd,
    const std::string& cgroup) noexcept {
  auto targetFd = getDirFd(cgroup);
  if (targetFd < 0) {
    return SYSTEM_ERROR(
        EINVAL, fmt::format("Invalid target cgroup dir: {}", cgroup));
  }
  SCOPE_EXIT {
    ::close(targetFd);
  };
  if (bpf_prog_detach2(progFd, targetFd, BPF_CGROUP_SOCK_OPS)) {
    int savedErrno = errno;
    return SYSTEM_ERROR(
        savedErrno,
        fmt::format(
            "Error while detaching bpf prog fd: {} to cgroup: {}, error {} ",
            progFd,
            cgroup,
            folly::errnoStr(savedErrno)));
  }
  VLOG(2) << fmt::format(
      "BPF program successfully detached from cgroup: {}", cgroup);
  return noSystemError();
}

} // namespace katran_tpr::BpfUtil
