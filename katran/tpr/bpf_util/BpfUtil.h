// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <folly/String.h>

#include <katran/tpr/bpf_util/SystemError.h>

namespace katran_tpr::BpfUtil {

constexpr int kNoFlags = 0;

SystemMaybe<folly::Unit> init() noexcept;

SystemMaybe<folly::Unit> setRLimit() noexcept;

int getDirFd(const std::string& path) noexcept;

SystemMaybe<folly::Unit> attachCgroupProg(
    int progFd,
    const std::string& cgroup,
    unsigned int flags) noexcept;

SystemMaybe<folly::Unit> detachCgroupProg(
    int progFd,
    const std::string& cgroup) noexcept;

template <class K, class V>
SystemMaybe<folly::Unit>
updateMapElement(int mapFd, const K& key, const V& value) noexcept {
  if (mapFd < 0) {
    return SYSTEM_ERROR(EINVAL, fmt::format("Invalid map-fd given: {}", mapFd));
  }
  if (::bpf_map_update_elem(mapFd, &key, &value, kNoFlags)) {
    int savedErrno = errno;
    return SYSTEM_ERROR(
        savedErrno,
        fmt::format(
            "Error while updating map: {}, error: {}",
            mapFd,
            folly::errnoStr(savedErrno)));
  }
  return noSystemError();
}

template <class K, class V>
SystemMaybe<folly::Unit>
lookupMapElement(int mapFd, const K& key, V& value) noexcept {
  if (mapFd < 0) {
    return SYSTEM_ERROR(EINVAL, fmt::format("Invalid map-fd given: {}", mapFd));
  }
  if (::bpf_map_lookup_elem(mapFd, &key, &value)) {
    int savedErrno = errno;
    return SYSTEM_ERROR(
        savedErrno,
        fmt::format(
            "Error while looking up in bpf map: {}, error: {}",
            mapFd,
            folly::errnoStr(savedErrno)));
  }
  return noSystemError();
}

} // namespace katran_tpr::BpfUtil
