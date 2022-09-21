// (c) Facebook, Inc. and its affiliates. Confidential and proprietary.

#include <fmt/core.h>
#include <fmt/format.h>
#include <folly/ScopeGuard.h>
#include <folly/String.h>
#include <folly/Unit.h>
#include <folly/portability/SysResource.h>
#include <folly/portability/Unistd.h>

#include <errno.h>
#include <glog/logging.h>

extern "C" {
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
}

#include <katran/tpr/TPRTypes.h>
#include <katran/tpr/TprBpfAdapter.h>

namespace katran_tpr {

constexpr int kMaxProgsToQuery = 1024;
const std::string kSockOpsObjName = "tcp_pkt_router_socksopt_obj";

#if False
static int libbpf_print_fn(
    enum libbpf_print_level level,
    const char* format,
    va_list args) {
  return vfprintf(stderr, format, args);
}
#endif

TprBpfAdapter::TprBpfAdapter() {
  VLOG(1) << "Enabled libbpf strict mode";
  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

#if False // Enable to get libbpf internal logs
  libbpf_set_print(libbpf_print_fn);
#endif
}

TprBpfAdapter::~TprBpfAdapter() {
  unload();
  // TODO detach cgroup prog as well?
}

folly::Expected<folly::Unit, std::system_error>
TprBpfAdapter::setRLimit() noexcept {
  if (isRlimitSet_) {
    return folly::Unit();
  }
  struct rlimit lck_mem = {};
  lck_mem.rlim_cur = RLIM_INFINITY;
  lck_mem.rlim_max = RLIM_INFINITY;
  if (setrlimit(RLIMIT_MEMLOCK, &lck_mem)) {
    int savedErrno = errno;
    return makeError(
        savedErrno,
        "Error while setting limit for locked memory, error:",
        folly::errnoStr(savedErrno));
  }
  isRlimitSet_ = true;
  return folly::Unit();
}

folly::Expected<folly::Unit, std::system_error> TprBpfAdapter::loadFromBuffer(
    char* buf,
    int buf_size) noexcept {
  if (already(BpfState::LOADED, getBpfState())) {
    return makeError(EALREADY, __func__, "BPF program is already loaded.");
  }
  LIBBPF_OPTS(
      ::bpf_object_open_opts,
      openOpts,
      .object_name = kSockOpsObjName.c_str(), );
  auto obj = ::bpf_object__open_mem(buf, buf_size, &openOpts);
  if (!obj) {
    int savedErrno = errno;
    return makeError(
        savedErrno,
        __func__,
        fmt::format(
            "Error while loading the byte buffer, error {} ",
            folly::errnoStr(savedErrno)));
  }
  return loadBpfObject(obj, kSockOpsObjName);
}

folly::Expected<folly::Unit, std::system_error> TprBpfAdapter::loadFromFile(
    const std::string& path) noexcept {
  if (already(BpfState::LOADED, getBpfState())) {
    return makeError(EALREADY, __func__, "BPF program is already loaded.");
  }
  auto obj = ::bpf_object__open(path.c_str());
  if (obj == nullptr) {
    int savedErrno = errno;
    return makeError(
        savedErrno,
        __func__,
        fmt::format(
            "Error while loading the byte buffer, error {} ",
            folly::errnoStr(savedErrno)));
  }
  return loadBpfObject(obj, path);
}

folly::Expected<folly::Unit, std::system_error> TprBpfAdapter::loadBpfObject(
    ::bpf_object* obj,
    const std::string& objName) noexcept {
  if (already(BpfState::LOADED, getBpfState()) || bpfObject_) {
    return makeError(EALREADY, __func__, "BPF program is already loaded.");
  }
  const auto err = ::libbpf_get_error(obj);
  if (err) {
    std::array<char, 128> errBuf{};
    ::libbpf_strerror(err, errBuf.data(), errBuf.size());
    return makeError(
        EINVAL, __func__, std::string(errBuf.begin(), errBuf.end()));
  }

  ::bpf_program* progIter;
  ::bpf_program* sockopsProg = nullptr;
  int progCount = 0;
  // check program section and validate it
  bpf_object__for_each_program(progIter, obj) {
    ++progCount;
    CHECK_LE(progCount, 1) << "More than one program supplied in bpf object: "
                           << objName;
    auto progName = ::bpf_program__name(progIter);
    VLOG(3) << fmt::format("[TPR] found  prog name={}", progName);
    bpfProgName_ = progName;
    sockopsProg = progIter;
  }

  if (::bpf_object__load(obj)) {
    int savedErrno = errno;
    auto errorStr = fmt::format(
        "error while trying to load bpf object: {}, error: {}",
        objName,
        folly::errnoStr(savedErrno));
    LOG(ERROR) << errorStr;
    ::bpf_object__close(obj);
    return makeError(savedErrno, __func__, errorStr);
  }
  CHECK_NOTNULL(sockopsProg);
  CHECK_EQ(bpf_program__type(sockopsProg), BPF_PROG_TYPE_SOCK_OPS);
  programFd_ = ::bpf_program__fd(sockopsProg);
  if (programFd_ < 0) {
    return makeError(
        programFd_,
        __func__,
        fmt::format("invalid program fd for prog: {}", bpfProgName_));
  }
  VLOG(3) << "sockops prog fd is set to " << programFd_;
  ::bpf_map* map;
  bpf_map__for_each(map, obj) {
    auto map_name = ::bpf_map__name(map);
    if (maps_.find(map_name) != maps_.end()) {
      ::bpf_object__close(obj);
      return makeError(
          EINVAL,
          __func__,
          fmt::format("BPF map name collision for map: {}", map_name));
    }
    maps_[map_name] = ::bpf_map__fd(map);
  }
  setBpfState(BpfState::LOADED);
  bpfObject_ = obj;
  VLOG(2) << "TPR BPF program successfully loaded";
  return folly::Unit();
}

folly::Expected<folly::Unit, std::system_error>
TprBpfAdapter::unload() noexcept {
  if (!already(BpfState::LOADED, getBpfState())) {
    LOG(INFO) << fmt::format("Bpf prog {} is no longer loaded", bpfProgName_);
    return folly::Unit();
  }
  if (programFd_ > 0) {
    ::close(programFd_);
    programFd_ = -1;
  }
  if (bpfObject_) {
    ::bpf_object__close(bpfObject_);
    bpfObject_ = nullptr;
  }
  for (auto& [map, fd] : maps_) {
    ::close(fd);
  }
  maps_.clear();
  VLOG(2) << "TPR BPF program successfully unloaded.";
  setBpfState(BpfState::INIT);
  return folly::Unit();
}

folly::Expected<folly::Unit, std::system_error> TprBpfAdapter::attachCgroupProg(
    int progFd,
    const std::string& cgroup,
    unsigned int flags) noexcept {
  if (!already(BpfState::LOADED, getBpfState())) {
    return makeError(EPERM, __func__, "BPF program is not yet loaded.");
  }
  auto targetFd = getDirFd(cgroup);
  if (targetFd < 0) {
    return makeError(
        EINVAL, __func__, fmt::format("Invalid target cgroup dir: {}", cgroup));
  }
  SCOPE_EXIT {
    ::close(targetFd);
  };
  if (programFd_ != progFd) {
    return makeError(
        EINVAL,
        __func__,
        fmt::format(
            "Got different bpf prog FD: {} than the one it has loaded: {} ",
            progFd,
            programFd_));
  }
  if (bpf_prog_attach(progFd, targetFd, BPF_CGROUP_SOCK_OPS, flags)) {
    int savedErrno = errno;
    return makeError(
        savedErrno,
        __func__,
        fmt::format(
            "Error while attaching bpf prog fd: {} to cgroup: {}, error {} ",
            progFd,
            cgroup,
            folly::errnoStr(savedErrno)));
  }
  LOG(INFO) << "[TPR] Successfully attached bpf prog at cgroup: " << cgroup;
  setBpfState(BpfState::ATTACHED);
  VLOG(2) << fmt::format(
      "TPR BPF program successfully attached to cgroup: {}", cgroup);
  return folly::Unit();
}

folly::Expected<folly::Unit, std::system_error> TprBpfAdapter::detachCgroupProg(
    int progFd,
    const std::string& cgroup) noexcept {
  auto targetFd = getDirFd(cgroup);
  if (targetFd < 0) {
    return makeError(
        EINVAL, __func__, fmt::format("Invalid target cgroup dir: {}", cgroup));
  }
  SCOPE_EXIT {
    ::close(targetFd);
  };
  if (programFd_ != progFd) {
    return makeError(
        EINVAL,
        __func__,
        fmt::format(
            "Got different bpf prog FD: {} than the one it has loaded: {} ",
            progFd,
            programFd_));
  }
  if (bpf_prog_detach2(progFd, targetFd, BPF_CGROUP_SOCK_OPS)) {
    int savedErrno = errno;
    return makeError(
        savedErrno,
        __func__,
        fmt::format(
            "Error while detaching bpf prog fd: {} to cgroup: {}, error {} ",
            progFd,
            cgroup,
            folly::errnoStr(savedErrno)));
  }
  setBpfState(BpfState::LOADED);
  VLOG(2) << fmt::format(
      "TPR BPF program successfully detached from cgroup: {}", cgroup);
  return folly::Unit();
}

folly::Expected<folly::Unit, std::system_error> TprBpfAdapter::detachCgroupProg(
    const std::string& cgroup) noexcept {
  auto targetFd = getDirFd(cgroup);
  if (targetFd < 0) {
    return makeError(
        EINVAL, __func__, fmt::format("Invalid target cgroup dir: {}", cgroup));
  }
  SCOPE_EXIT {
    ::close(targetFd);
  };
  auto res = bpf_prog_detach(targetFd, BPF_CGROUP_SOCK_OPS);
  if (res) {
    VLOG(2) << "detaching bpf progs explicitly by fd";
    auto mayBeProgIds = getCgroupProgsIds(cgroup);
    if (mayBeProgIds.hasError()) {
      return makeError(mayBeProgIds.error(), __func__);
    }
    auto progIds = std::move(*mayBeProgIds);
    if (progIds.empty()) {
      // if there's no program attached, then clean exist
      return folly::Unit();
    }
    for (auto& id : progIds) {
      VLOG(2) << "detaching program id: " << id;
      auto fd = ::bpf_prog_get_fd_by_id(id);
      if (fd < 0) {
        return makeError(
            EINVAL, __func__, fmt::format("Invalid BPF prog FD: {}", fd));
      }
      // do not let the fd leak
      SCOPE_EXIT {
        ::close(fd);
      };
      res = bpf_prog_detach2(fd, targetFd, BPF_CGROUP_SOCK_OPS);
      if (res) {
        // instead of bailing, LOG and try another one
        LOG(ERROR) << fmt::format(
            "Failed to detach fd: {} from cgroup: {}", fd, cgroup);
        continue;
      }
    }
  }
  setBpfState(BpfState::LOADED);
  VLOG(2) << fmt::format(
      "TPR BPF program successfully detached from cgroup: {}", cgroup);
  return folly::Unit();
}

folly::Expected<folly::Unit, std::system_error>
TprBpfAdapter::detachCgroupProgByPrefix(
    const std::string& cgroup,
    const std::string& progPrefix) noexcept {
  auto targetFd = getDirFd(cgroup);
  if (targetFd < 0) {
    return makeError(
        EINVAL, __func__, fmt::format("Invalid target cgroup dir: {}", cgroup));
  }
  SCOPE_EXIT {
    ::close(targetFd);
  };
  auto mayBeProgIds = getCgroupProgsIds(cgroup);
  if (mayBeProgIds.hasError()) {
    return makeError(mayBeProgIds.error(), __func__);
  }
  auto progIds = std::move(*mayBeProgIds);
  if (progIds.empty()) {
    // if there's no program attached, then clean exist
    return folly::Unit();
  }
  for (auto& id : progIds) {
    auto fd = ::bpf_prog_get_fd_by_id(id);
    if (fd < 0) {
      return makeError(
          EINVAL, __func__, fmt::format("Invalid BPF prog FD: {}", fd));
    }
    // do not let the fd leak
    SCOPE_EXIT {
      ::close(fd);
    };
    auto mayBeProgInfo = getBpfProgInfo(fd);
    if (mayBeProgInfo.hasError()) {
      return makeError(mayBeProgInfo.error(), __func__);
    }
    folly::StringPiece progName = mayBeProgInfo->name;
    if (progName.startsWith(progPrefix)) {
      VLOG(2) << fmt::format(
          "Detaching bpf-prog {} with id {} by prefix match; given prefix: {}",
          progName,
          id,
          progPrefix);
      auto res = bpf_prog_detach2(fd, targetFd, BPF_CGROUP_SOCK_OPS);
      if (res) {
        // instead of bailing, LOG and try another one
        LOG(ERROR) << fmt::format(
            "Failed to detach fd: {} from cgroup: {}", fd, cgroup);
      }
    }
  }
  setBpfState(BpfState::LOADED);
  VLOG(2) << fmt::format(
      "TPR BPF program successfully detached from cgroup: {}", cgroup);
  return folly::Unit();
}

folly::Expected<std::vector<uint32_t>, std::system_error>
TprBpfAdapter::getCgroupProgsIds(const std::string& cgroup) noexcept {
  std::array<uint32_t, kMaxProgsToQuery> progs{};
  std::vector<uint32_t> result{};
  uint32_t prog_count = kMaxProgsToQuery;
  uint32_t flags;

  auto cgroupFd = getDirFd(cgroup);
  if (cgroupFd < 0) {
    return makeError(
        EINVAL, __func__, fmt::format("Invalid target cgroup dir: {}", cgroup));
  }
  SCOPE_EXIT {
    ::close(cgroupFd);
  };
  int query_result = bpf_prog_query(
      cgroupFd, BPF_CGROUP_SOCK_OPS, 0, &flags, progs.data(), &prog_count);
  if (!query_result) {
    for (uint32_t i = 0; i < prog_count; i++) {
      result.push_back(progs[i]);
    }
  }
  return result;
}

folly::Expected<int, std::system_error>
TprBpfAdapter::getBpfProgramFd() noexcept {
  if (!already(BpfState::LOADED, getBpfState())) {
    return makeError(EINVAL, __func__, "BPF program is not yet loaded.");
  }
  return programFd_;
}

folly::Expected<int, std::system_error> TprBpfAdapter::getMapFdByName(
    const std::string& name) noexcept {
  if (!already(BpfState::LOADED, getBpfState())) {
    return makeError(EINVAL, __func__, "BPF program is not yet loaded.");
  }
  auto iter = maps_.find(name);
  if (iter == maps_.end()) {
    return makeError(
        EINVAL, __func__, fmt::format("Cannot find map: {}", name));
  }
  return iter->second;
}

folly::Expected<folly::Unit, std::system_error> TprBpfAdapter::getBpfProgInfo(
    int progFd,
    ::bpf_prog_info& info) noexcept {
  uint32_t infoLen = sizeof(info);
  if (::bpf_obj_get_info_by_fd(progFd, &info, &infoLen)) {
    int savedErrno = errno;
    return makeError(
        savedErrno,
        __func__,
        fmt::format(
            "Error while looking up info for prog fd: {}, error {} ",
            progFd,
            folly::errnoStr(savedErrno)));
  }
  return folly::Unit();
}

folly::Expected<bpf_prog_info, std::system_error> TprBpfAdapter::getBpfProgInfo(
    int progFd) noexcept {
  ::bpf_prog_info info = {};
  auto res = getBpfProgInfo(progFd, info);
  if (res.hasError()) {
    return makeError(res.error(), __func__);
  }
  return info;
}

int TprBpfAdapter::getDirFd(const std::string& path) {
  return ::open(path.c_str(), O_DIRECTORY, O_RDONLY);
}

void TprBpfAdapter::setBpfState(BpfState newState) noexcept {
  VLOG(4) << fmt::format("setBpfState: state={}", toString(newState));
  // TODO add validation for state transition if we add more states.
  state_ = newState;
}

bool TprBpfAdapter::already(
    BpfState checkState,
    BpfState currentState) noexcept {
  if (currentState == BpfState::UNKNOWN_STATE) {
    // we dont know much about unknown state
    LOG(ERROR) << "currentState=UNKNOWN_STATE";
    return false;
  } else if (checkState == currentState) {
    // every known state is already itself.
    return true;
  } else if (!isErrorState(checkState) && !isErrorState(currentState)) {
    // non-error states are sequentially ordered,
    // therefore we can just compare
    return currentState > checkState;
  } else {
    return false;
  }
}

} // namespace katran_tpr
