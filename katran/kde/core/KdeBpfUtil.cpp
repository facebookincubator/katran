#include <katran/kde/core/KdeBpfUtil.h>

#include <bpf/bpf.h>
#include <fmt/format.h>
#include <glog/logging.h>
#include <sys/mman.h>
#include <cstring>
#include <filesystem>
#include <system_error>
#include <vector>

#include <folly/ScopeGuard.h>
#include <folly/String.h>
#include <folly/portability/Filesystem.h>

#include <katran/kde/consts.h>
#include <katran/lib/BpfAdapter.h>

namespace katran_tpr {

folly::Expected<int, std::system_error> KdeBpfUtil::openPinnedObj(
    const std::string& item) {
  std::string pinnedPath = getPinPath(item);
  int fd = bpf_obj_get(pinnedPath.c_str());
  if (fd < 0) {
    int err = errno;
    std::string errMsg = fmt::format(
        "Failed to open pinned BPF object {}: {}",
        pinnedPath,
        folly::errnoStr(err));
    LOG(ERROR) << errMsg;
    return folly::makeUnexpected(
        std::system_error(err, std::generic_category(), errMsg));
  }
  return fd;
}

folly::Expected<int, std::system_error> KdeBpfUtil::findMapFdFromProgFd(
    int fd,
    const std::string& mapName) {
  struct bpf_prog_info progInfo = {};
  uint32_t bpfProgInfoLen = sizeof(progInfo);
  memset(&progInfo, 0, bpfProgInfoLen);
  if (bpf_prog_get_info_by_fd(fd, &progInfo, &bpfProgInfoLen)) {
    int err = errno;
    std::string errMsg = fmt::format(
        "Failed to get info of BPF prog, errno: {}", folly::errnoStr(err));
    LOG(ERROR) << errMsg;
    return folly::makeUnexpected(
        std::system_error(err, std::generic_category(), errMsg));
  }

  uint32_t mapsCount = progInfo.nr_map_ids;
  memset(&progInfo, 0, bpfProgInfoLen);
  progInfo.nr_map_ids = mapsCount;
  uint32_t mapIds[mapsCount];
  progInfo.map_ids = (uint64_t)(mapIds);
  if (bpf_prog_get_info_by_fd(fd, &progInfo, &bpfProgInfoLen)) {
    int err = errno;
    std::string errMsg = fmt::format(
        "Failed to get info with maps of BPF prog, errno: {}",
        folly::errnoStr(err));
    LOG(ERROR) << errMsg;
    return folly::makeUnexpected(
        std::system_error(err, std::generic_category(), errMsg));
  }

  struct bpf_map_info mapInfo = {};
  uint32_t bpfMapInfoLen = sizeof(mapInfo);
  int mapFd = -1;
  for (int i = 0; i < progInfo.nr_map_ids; i++) {
    int tempFd = bpf_map_get_fd_by_id(mapIds[i]);
    if (tempFd < 0) {
      int err = errno;
      std::string errMsg = fmt::format(
          "Failed to get BPF fd of bpf map id: {}, errno: {}",
          mapIds[i],
          folly::errnoStr(err));
      LOG(ERROR) << errMsg;
      return folly::makeUnexpected(
          std::system_error(err, std::generic_category(), errMsg));
    }

    memset(&mapInfo, 0, bpfMapInfoLen);
    if (bpf_map_get_info_by_fd(tempFd, &mapInfo, &bpfMapInfoLen)) {
      int err = errno;
      std::string errMsg = fmt::format(
          "Failed to get info of BPF map, errno: {}", folly::errnoStr(err));
      LOG(ERROR) << errMsg;
      return folly::makeUnexpected(
          std::system_error(err, std::generic_category(), errMsg));
    }
    if (mapInfo.name == mapName) {
      mapFd = tempFd;
      break;
    } else {
      VLOG(3) << "Skipped map name: " << mapInfo.name << " id: " << mapIds[i];
      close(tempFd);
    }
  }

  if (mapFd < 0) {
    std::string errMsg = fmt::format("Failed to find map: {}", mapName);
    LOG(ERROR) << errMsg;
    return folly::makeUnexpected(
        std::system_error(0, std::generic_category(), errMsg));
  } else {
    return mapFd;
  }
}

template <class T>
folly::Expected<const T*, std::system_error> skeletonMapFromFd(int mapFd) {
  void* mapAddr = ::mmap(
      nullptr,
      sizeof(T),
      PROT_READ,
      MAP_SHARED,
      mapFd,
      /*__offset=*/0);
  if (mapAddr == MAP_FAILED) {
    int err = errno;
    std::string errMsg =
        fmt::format("Failed to mmap BPF map, errno: {}", folly::errnoStr(err));
    LOG(ERROR) << errMsg;
    return folly::makeUnexpected(
        std::system_error(err, std::generic_category(), errMsg));
  }
  return reinterpret_cast<const T*>(mapAddr);
}

template <class T>
folly::Expected<folly::Unit, std::system_error> unmapSkeletonMap(const T* map) {
  if (::munmap((void*)map, sizeof(T))) {
    int err = errno;
    std::string errMsg = fmt::format(
        "Failed to munmap BPF map, errno: {}", folly::errnoStr(err));
    LOG(ERROR) << errMsg;
    return folly::makeUnexpected(
        std::system_error(err, std::generic_category(), errMsg));
  }
  return folly::Unit();
}

folly::Expected<SockOpsBssMap, std::system_error>
KdeBpfUtil::findSockOpsBssMap() {
  auto maybeFd = openPinnedObj(KdeSoBssName);
  if (maybeFd.hasError()) {
    return folly::makeUnexpected(maybeFd.error());
  }
  SockOpsBssMap map;
  map.mapFd_ = *maybeFd;
  auto maybeMap = skeletonMapFromFd<SockOpsBssMap::MapType>(map.mapFd_);
  if (maybeMap.hasError()) {
    return folly::makeUnexpected(maybeMap.error());
  }
  map.map_ = maybeMap.value();
  return std::move(map);
}

folly::Expected<int, std::system_error> KdeBpfUtil::findSkStoreMapFd() {
  auto progFdExp = openPinnedObj(KdeSockOpsProgName);
  if (progFdExp.hasError()) {
    return folly::makeUnexpected(progFdExp.error());
  }
  int progFd = progFdExp.value();
  SCOPE_EXIT {
    close(progFd);
  };
  return findMapFdFromProgFd(progFd, "katran_de_sk_st");
}

folly::Expected<TcBssMap, std::system_error> KdeBpfUtil::findTcBssMap() {
  auto maybeFd = openPinnedObj(KdeTcBssName);
  if (maybeFd.hasError()) {
    return folly::makeUnexpected(maybeFd.error());
  }
  TcBssMap map;
  map.mapFd_ = *maybeFd;
  auto maybeMap = skeletonMapFromFd<TcBssMap::MapType>(map.mapFd_);
  if (maybeMap.hasError()) {
    return folly::makeUnexpected(maybeMap.error());
  }
  map.map_ = maybeMap.value();
  return std::move(map);
}

kde_stats KdeBpfUtil::aggregateSoStats(
    const katran_de_so_bpf::katran_de_so_bpf__bss& bss) {
  kde_stats result = {};
  uint32_t numCpus = katran::BpfAdapter::getPossibleCpus();
  for (uint32_t i = 0; i < numCpus; i++) {
    kde_stats statsForCpu = bss.g_stats[i];
    result.error_sys_calls += statsForCpu.error_sys_calls;

    result.client_opt_set += statsForCpu.client_opt_set;
    result.client_error_write_opt += statsForCpu.client_error_write_opt;
    result.client_no_kde += statsForCpu.client_no_kde;
    result.client_opt_received += statsForCpu.client_opt_received;
    result.client_sk_stored += statsForCpu.client_sk_stored;
    result.client_retrans += statsForCpu.client_retrans;
    result.client_tuple_store_stale_entries +=
        statsForCpu.client_tuple_store_stale_entries;
    result.client_tuple_stored += statsForCpu.client_tuple_stored;
    result.client_tuple_removed += statsForCpu.client_tuple_removed;
    result.client_error_tuple_store += statsForCpu.client_error_tuple_store;
    result.client_error_nat_missing += statsForCpu.client_error_nat_missing;

    result.server_error_write_opt += statsForCpu.server_error_write_opt;
    result.server_error_setso += statsForCpu.server_error_setso;
    result.server_error_set_cb += statsForCpu.server_error_set_cb;
    result.server_error_unset_cb += statsForCpu.server_error_unset_cb;
    result.server_error_load_hdr += statsForCpu.server_error_load_hdr;
    result.server_error_reserve += statsForCpu.server_error_reserve;
    result.server_error_no_saved_syn += statsForCpu.server_error_no_saved_syn;
    result.server_error_synack_map_update +=
        statsForCpu.server_error_synack_map_update;
    result.server_opt_set += statsForCpu.server_opt_set;
    result.server_nat_opt_set += statsForCpu.server_nat_opt_set;
    result.server_no_kde_syn += statsForCpu.server_no_kde_syn;
    result.server_no_kde += statsForCpu.server_no_kde;
    result.server_rx_zone_v1 += statsForCpu.server_rx_zone_v1;
    result.server_rx_zone_unknown_acc += statsForCpu.server_rx_zone_unknown_acc;
    result.server_rx_zone_unknown_rej += statsForCpu.server_rx_zone_unknown_rej;
    for (int j = 0; j < KDE_MAX_ZONES; j++) {
      result.server_rx_zone[j].acc += statsForCpu.server_rx_zone[j].acc;
      result.server_rx_zone[j].rej += statsForCpu.server_rx_zone[j].rej;
    }
    result.server_retrans_synack += statsForCpu.server_retrans_synack;
    result.server_directip_blackhole += statsForCpu.server_directip_blackhole;
  }
  return result;
}

kde_tc_stats KdeBpfUtil::aggregateTcStats(
    const katran_de_tc_bpf::katran_de_tc_bpf__bss& bss) {
  kde_tc_stats result = {};
  uint32_t numCpus = katran::BpfAdapter::getPossibleCpus();
  for (uint32_t i = 0; i < numCpus; i++) {
    kde_tc_stats statsForCpu = bss.g_tc_stats[i];
    result.error_sys_calls += statsForCpu.error_sys_calls;
    result.nat_replace_fail += statsForCpu.nat_replace_fail;
    result.no_sk_store += statsForCpu.no_sk_store;
    result.in_sk_store += statsForCpu.in_sk_store;
    result.no_tuple_store += statsForCpu.no_tuple_store;
    result.in_tuple_store += statsForCpu.in_tuple_store;
    result.encap_fail += statsForCpu.encap_fail;
    result.encap_ok += statsForCpu.encap_ok;
    result.encap_bytes += statsForCpu.encap_bytes;
    result.encap_payload_bytes += statsForCpu.encap_payload_bytes;
    result.error_parse_src += statsForCpu.error_parse_src;
    result.conns_encapped += statsForCpu.conns_encapped;
  }
  return result;
}

kde_stats KdeBpfUtil::diffSoStats(const kde_stats& lhs, const kde_stats& rhs) {
  kde_stats result = {};
  result.error_sys_calls = lhs.error_sys_calls - rhs.error_sys_calls;

  result.client_opt_set = lhs.client_opt_set - rhs.client_opt_set;
  result.client_error_write_opt =
      lhs.client_error_write_opt - rhs.client_error_write_opt;
  result.client_no_kde = lhs.client_no_kde - rhs.client_no_kde;
  result.client_opt_received =
      lhs.client_opt_received - rhs.client_opt_received;
  result.client_sk_stored = lhs.client_sk_stored - rhs.client_sk_stored;
  result.client_retrans = lhs.client_retrans - rhs.client_retrans;
  result.client_error_tuple_store =
      lhs.client_error_tuple_store - rhs.client_error_tuple_store;
  result.client_error_nat_missing =
      lhs.client_error_nat_missing - rhs.client_error_nat_missing;

  result.server_error_write_opt =
      lhs.server_error_write_opt - rhs.server_error_write_opt;
  result.server_error_setso = lhs.server_error_setso - rhs.server_error_setso;
  result.server_error_set_cb =
      lhs.server_error_set_cb - rhs.server_error_set_cb;
  result.server_error_unset_cb =
      lhs.server_error_unset_cb - rhs.server_error_unset_cb;
  result.server_error_load_hdr =
      lhs.server_error_load_hdr - rhs.server_error_load_hdr;
  result.server_error_reserve =
      lhs.server_error_reserve - rhs.server_error_reserve;
  result.server_error_no_saved_syn =
      lhs.server_error_no_saved_syn - rhs.server_error_no_saved_syn;
  result.server_error_synack_map_update =
      lhs.server_error_synack_map_update - rhs.server_error_synack_map_update;
  result.server_opt_set = lhs.server_opt_set - rhs.server_opt_set;
  result.server_no_kde_syn = lhs.server_no_kde_syn - rhs.server_no_kde_syn;
  result.server_no_kde = lhs.server_no_kde - rhs.server_no_kde;
  result.server_rx_zone_v1 = lhs.server_rx_zone_v1 - rhs.server_rx_zone_v1;
  result.server_rx_zone_unknown_acc =
      lhs.server_rx_zone_unknown_acc - rhs.server_rx_zone_unknown_acc;
  result.server_rx_zone_unknown_rej =
      lhs.server_rx_zone_unknown_rej - rhs.server_rx_zone_unknown_rej;
  for (int i = 0; i < KDE_MAX_ZONES; i++) {
    result.server_rx_zone[i].acc =
        lhs.server_rx_zone[i].acc - rhs.server_rx_zone[i].acc;
    result.server_rx_zone[i].rej =
        lhs.server_rx_zone[i].rej - rhs.server_rx_zone[i].rej;
  }
  result.server_retrans_synack =
      lhs.server_retrans_synack - rhs.server_retrans_synack;
  result.server_directip_blackhole =
      lhs.server_directip_blackhole - rhs.server_directip_blackhole;
  result.server_nat_opt_set = lhs.server_nat_opt_set - rhs.server_nat_opt_set;
  return result;
}

kde_tc_stats KdeBpfUtil::diffTcStats(
    const kde_tc_stats& lhs,
    const kde_tc_stats& rhs) {
  kde_tc_stats result = {};
  result.error_sys_calls = lhs.error_sys_calls - rhs.error_sys_calls;
  result.no_sk_store = lhs.no_sk_store - rhs.no_sk_store;
  result.in_sk_store = lhs.in_sk_store - rhs.in_sk_store;
  result.no_tuple_store = lhs.no_tuple_store - rhs.no_tuple_store;
  result.in_tuple_store = lhs.in_tuple_store - rhs.in_tuple_store;
  result.encap_fail = lhs.encap_fail - rhs.encap_fail;
  result.encap_ok = lhs.encap_ok - rhs.encap_ok;
  result.encap_bytes = lhs.encap_bytes - rhs.encap_bytes;
  result.encap_payload_bytes =
      lhs.encap_payload_bytes - rhs.encap_payload_bytes;
  result.error_parse_src = lhs.error_parse_src - rhs.error_parse_src;
  result.conns_encapped = lhs.conns_encapped - rhs.conns_encapped;
  result.nat_replace_fail = lhs.nat_replace_fail - rhs.nat_replace_fail;
  return result;
}

uint64_t KdeBpfUtil::sumServerErrors(const kde_stats& stats) {
  return stats.error_sys_calls + stats.server_error_write_opt +
      stats.server_error_setso + stats.server_error_set_cb +
      stats.server_error_unset_cb + stats.server_error_load_hdr +
      stats.server_error_reserve + stats.server_error_no_saved_syn +
      stats.server_error_synack_map_update;
}

template <class RoData>
folly::Expected<uint32_t, std::system_error> KdeBpfUtil::readProgVersion(
    const std::string& progName) {
  auto maybeProgFd = openPinnedObj(progName);
  if (maybeProgFd.hasError()) {
    return folly::makeUnexpected(maybeProgFd.error());
  }
  int progFd = *maybeProgFd;
  SCOPE_EXIT {
    ::close(progFd);
  };

  auto maybeRodataFd = findMapFdFromProgFd(progFd, "katran_d.rodata");
  if (maybeRodataFd.hasError()) {
    return folly::makeUnexpected(maybeRodataFd.error());
  }
  int rodataFd = *maybeRodataFd;
  SCOPE_EXIT {
    ::close(rodataFd);
  };

  auto maybeMap = skeletonMapFromFd<RoData>(rodataFd);
  if (maybeMap.hasError()) {
    return folly::makeUnexpected(maybeMap.error());
  }
  uint32_t version = (*maybeMap)->bpf_metadata_kde_bpf_version.version;
  unmapSkeletonMap(*maybeMap);
  return version;
}

folly::Expected<uint32_t, std::system_error> KdeBpfUtil::findSockOpsVersion() {
  return readProgVersion<katran_de_so_bpf::katran_de_so_bpf__rodata>(
      KdeSockOpsProgName);
}

folly::Expected<uint32_t, std::system_error> KdeBpfUtil::findTcVersion() {
  return readProgVersion<katran_de_tc_bpf::katran_de_tc_bpf__rodata>(
      KdeTcProgName);
}

// bpf_obj_pin() requires a bpffs mount point. Prefer KATRAN_DE_PIN_PATH, then
// LIBBPF_BPF_TOKEN_PATH (when bpffs/token mount is exposed there), falling back
// to /sys/fs/bpf/.
std::string KdeBpfUtil::getPinPath(const std::string& item) {
  const char* tokenPath = std::getenv("LIBBPF_BPF_TOKEN_PATH");
  const char* pinPath = std::getenv("KATRAN_DE_PIN_PATH");
  std::string b = "/sys/fs/bpf/";
  if (pinPath && *pinPath) {
    b = pinPath;
  } else if (tokenPath && *tokenPath) {
    b = tokenPath;
  }
  return (std::filesystem::path(b) / item).string();
}
} // namespace katran_tpr
