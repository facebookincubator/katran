#pragma once

#include <linux/types.h>
#include <unistd.h>
#include <system_error>

#include <folly/Expected.h>

// kde_types.h must be before the skel.h as they refrence types
#include "katran/kde/bpf/kde_types.h"

#include <katran/kde/bpf/katran_de_so_bpf.skel.h>
#include <katran/kde/bpf/katran_de_tc_bpf.skel.h>

namespace katran_tpr {

template <class T>
folly::Expected<const T*, std::system_error> skeletonMapFromFd(int mapFd);
template <class T>
folly::Expected<folly::Unit, std::system_error> unmapSkeletonMap(const T* map);

template <class T>
class SkeletonMap {
 public:
  using MapType = T;
  SkeletonMap() = default;
  SkeletonMap(const SkeletonMap&) = delete;
  SkeletonMap& operator=(const SkeletonMap&) = delete;
  SkeletonMap(SkeletonMap&& other) noexcept {
    moveObj(std::move(other));
  }
  SkeletonMap& operator=(SkeletonMap&& other) noexcept {
    moveObj(std::move(other));
    return *this;
  }
  ~SkeletonMap() {
    close(progFd_);
    close(mapFd_);
    if (map_) {
      unmapSkeletonMap(map_);
    }
  }
  void moveObj(SkeletonMap&& other) {
    progFd_ = other.progFd_;
    mapFd_ = other.mapFd_;
    map_ = other.map_;
    other.progFd_ = -1;
    other.mapFd_ = -1;
    other.map_ = nullptr;
  }
  int progFd_{-1};
  int mapFd_{-1};
  const T* map_{nullptr};
};

using TcBssMap = SkeletonMap<katran_de_tc_bpf::katran_de_tc_bpf__bss>;
using SockOpsBssMap = SkeletonMap<katran_de_so_bpf::katran_de_so_bpf__bss>;

class KdeBpfUtil {
 public:
  static folly::Expected<SockOpsBssMap, std::system_error> findSockOpsBssMap(
      const std::string& cgroupPath);

  static folly::Expected<TcBssMap, std::system_error> findTcBssMap(
      const std::string& iface);

  static folly::Expected<int, std::system_error> findSkStoreMapFd(
      const std::string& cgroupPath);

  static kde_stats aggregateSoStats(
      const katran_de_so_bpf::katran_de_so_bpf__bss& bss);
  static kde_tc_stats aggregateTcStats(
      const katran_de_tc_bpf::katran_de_tc_bpf__bss& bss);

  static kde_stats diffSoStats(const kde_stats& lhs, const kde_stats& rhs);
  static kde_tc_stats diffTcStats(
      const kde_tc_stats& lhs,
      const kde_tc_stats& rhs);

  static uint64_t sumServerErrors(const kde_stats& stats);

  static folly::Expected<uint32_t, std::system_error> findSockOpsVersion(
      const std::string& cgroupPath);
  static folly::Expected<uint32_t, std::system_error> findTcVersion(
      const std::string& iface);
  static uint32_t getCurrentKdeProgVersion() {
    return KDE_PROG_VERSION;
  }

  static std::string getPinPath(const std::string& item);

 private:
  static constexpr auto kBpfMetadataKdeVersion = "bpf_metadata_kde_version";

  static folly::Expected<int, std::system_error> findSockOpsProgFd(
      const std::string& cgroupPath);
  static folly::Expected<int, std::system_error> findTcProgFd(
      const std::string& iface);
  static folly::Expected<int, std::system_error> findMapFdFromProgFd(
      int progFd,
      const std::string& mapName);
};

} // namespace katran_tpr
