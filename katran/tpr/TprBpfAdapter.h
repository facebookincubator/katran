// (c) Facebook, Inc. and its affiliates. Confidential and proprietary.

#pragma once

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <folly/Expected.h>
#include <folly/String.h>
#include <folly/container/F14Map.h>
#include <cstdint>
#include <string>
#include <vector>

#include <katran/tpr/TPRTypes.h>

namespace katran_tpr {

/**
 * Class that interfaces with the BPF layer.
 * NOTE: this class is not thread safe.
 */
class TprBpfAdapter {
 public:
  // helpful to keep track of internal state w.r.t the state of the bpf program
  enum class BpfState : uint8_t {
    INIT = 0,
    LOADED = 1,
    ATTACHED = 2,
    UNKNOWN_STATE = 255
  };

  TprBpfAdapter();

  ~TprBpfAdapter();

  folly::Expected<folly::Unit, std::system_error> setRLimit() noexcept;

  /**
   * Loads the given BPF program supplied as byte buffer.
   * @param char* buf ptr to buffer with bpf's elf object
   * @param int buf_size size of the buffer
   * @return folly::Unit in case of success, else error.
   */
  folly::Expected<folly::Unit, std::system_error> loadFromBuffer(
      char* buf,
      int buf_size) noexcept;

  /**
   * Loads the given BPF program provides as path to the object file.
   * @param string path: path to bpf object file to load
   * @return folly::Unit in case of success, else error.
   */
  folly::Expected<folly::Unit, std::system_error> loadFromFile(
      const std::string& path) noexcept;

  /**
   * Loads the given BPF program provides as bpf_object.
   * @param bpf_object* obj bpf object to load
   * @param string objName: name of the loaded bpf object
   * @return folly::Unit in case of success, else error.
   */
  folly::Expected<folly::Unit, std::system_error> loadBpfObject(
      ::bpf_object* obj,
      const std::string& objName) noexcept;

  /**
   * Unloads if the bpf program is already loaded.
   * No-op if the program is not loaded.
   * @return folly::Unit in case of success, else error.
   */
  folly::Expected<folly::Unit, std::system_error> unload() noexcept;

  /**
   * Attaches bpf prog to specified cgroup with bpf_attach_type
   * BPF_CGROUP_SOCK_OPS
   * @param int progFd descriptor of the program
   * @param string path to cgroup directory
   * @param unsigned int flags
   * @return folly::Unit in case of success, else error.
   */
  folly::Expected<folly::Unit, std::system_error> attachCgroupProg(
      int progFd,
      const std::string& cgroup,
      unsigned int flags) noexcept;

  /**
   * Detaches *all* bpf progs from the specified cgroup dir with
   * bpf_attach_type BPF_CGROUP_SOCK_OPS
   * @param string path to cgroup directory
   * @return folly::Unit in case of success, else error.
   *   */
  folly::Expected<folly::Unit, std::system_error> detachCgroupProg(
      const std::string& cgroup) noexcept;

  /**
   * Detaches specified (by fd) bpf progs from specified cgroup with
   * bpf_attach_type BPF_CGROUP_SOCK_OPS
   * @param int bpf prog fd
   * @param string path to cgroup directory
   * @return folly::Unit in case of success, else error.
   */
  folly::Expected<folly::Unit, std::system_error> detachCgroupProg(
      int progFd,
      const std::string& cgroup) noexcept;

  /**
   * Detaches *all* bpf progs with matching program name prefix from the
   * specified cgroup with bpf_attach_type BPF_CGROUP_SOCK_OPS
   * @param string path to cgroup directory
   * @param string progPrefix Prefix to match with each bpf-program name in
   *        the specified group before detaching the program
   * @return folly::Unit in case of success, else error.
   */
  folly::Expected<folly::Unit, std::system_error> detachCgroupProgByPrefix(
      const std::string& cgroup,
      const std::string& progPrefix) noexcept;

  /**
   * Returns a list of fds of all attached bpf progs with specified type to
   * specified cgroup with bpf_attach_type BPF_CGROUP_SOCK_OPS
   * @param string path to cgroup directory
   * @return vector int of fds of attached bpf progs
   */
  folly::Expected<std::vector<uint32_t>, std::system_error> getCgroupProgsIds(
      const std::string& cgroup) noexcept;

  /**
   * Returns the fd of the sockops Bpf program (if loaded)
   */
  folly::Expected<int, std::system_error> getBpfProgramFd() noexcept;

  /**
   * helper function to get info about a valid bpf program
   * @param int Fd of a valid bpf program
   * @return bpf_prog_info object with info about the given program
   */
  folly::Expected<folly::Unit, std::system_error> getBpfProgInfo(
      int progFd,
      ::bpf_prog_info& info) noexcept;

  /**
   * helper function to get info about a valid bpf program
   * @param int Fd of a valid bpf program
   * @return bpf_prog_info object with info about the given program
   */
  folly::Expected<bpf_prog_info, std::system_error> getBpfProgInfo(
      int progFd) noexcept;

  /**
   * Returns the fd of the Bpf map if bpf program is loaded
   */
  folly::Expected<int, std::system_error> getMapFdByName(
      const std::string& name) noexcept;

  template <class K, class V>
  folly::Expected<folly::Unit, std::system_error>
  updateMapElement(int mapFd, const K& key, const V& value) noexcept {
    if (mapFd < 0) {
      return makeError(
          EINVAL, __func__, fmt::format("Invalid map-fd given: {}", mapFd));
    }
    if (::bpf_map_update_elem(mapFd, &key, &value, kNoFlags)) {
      int savedErrno = errno;
      return makeError(
          savedErrno,
          __func__,
          fmt::format(
              "Error while updating map: {}, error: {}",
              mapFd,
              folly::errnoStr(savedErrno)));
    }
    return folly::Unit();
  }

  template <class K, class V>
  folly::Expected<folly::Unit, std::system_error>
  lookupMapElement(int mapFd, const K& key, V& value) noexcept {
    if (mapFd < 0) {
      return makeError(
          EINVAL, __func__, fmt::format("Invalid map-fd given: {}", mapFd));
    }
    if (::bpf_map_lookup_elem(mapFd, &key, &value)) {
      int savedErrno = errno;
      return makeError(
          savedErrno,
          __func__,
          fmt::format(
              "Error while looking up in bpf map: {}, error: {}",
              mapFd,
              folly::errnoStr(savedErrno)));
    }
    return folly::Unit();
  }

  template <class K>
  folly::Expected<folly::Unit, std::system_error> deleteMapElement(
      int mapFd,
      const K& key) noexcept {
    if (mapFd < 0) {
      return makeError(
          EINVAL, __func__, fmt::format("Invalid map-fd given: {}", mapFd));
    }
    if (::bpf_map_delete_elem(mapFd, &key)) {
      int savedErrno = errno;
      return makeError(
          savedErrno,
          __func__,
          fmt::format(
              "Error while deleting item in map: {}, error: {}",
              mapFd,
              folly::errnoStr(savedErrno)));
    }
    return folly::Unit();
  }

  /**
   open specified dir and returns it's fd.
   * used to get cgroup's fd from path
   * returns -1 on failure
   */
  int getDirFd(const std::string& path);

  /**
   * Returns the current state w.r.t the BPF program
   */
  BpfState getBpfState() const noexcept {
    return state_;
  }

  // Disallow accidental copy of this class
  TprBpfAdapter(TprBpfAdapter const&) = delete;
  TprBpfAdapter& operator=(TprBpfAdapter const&) = delete;

 private:
  /**
   * Checks if the state has already surpassed the given state.
   * This is with the expectatation of state progress:
   *   INIT -> LOADED -> ATTACHED
   */
  inline bool already(BpfState checkState, BpfState currentState) noexcept;

  inline bool isErrorState(BpfState state) const noexcept {
    return state == BpfState::UNKNOWN_STATE;
  }

  void setBpfState(BpfState newState) noexcept;

  static const char* toString(BpfState reason) {
    switch (reason) {
      case BpfState::INIT:
        return "INIT";
      case BpfState::LOADED:
        return "LOADED";
      case BpfState::ATTACHED:
        return "ATTACHED";
      case BpfState::UNKNOWN_STATE:
        return "UNKNOWN_ERROR";
      default:
        throw std::runtime_error("Undefined BpfState");
    }
  }

  std::unordered_map<std::string, int> maps_;
  int programFd_{-1};
  std::string bpfProgName_;
  bpf_object* bpfObject_{nullptr};
  BpfState state_{BpfState::INIT};
  bool isRlimitSet_{false};
};

} // namespace katran_tpr
