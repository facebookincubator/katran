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

#pragma once
#include <string>
#include <unordered_map>

#include "BpfLoader.h"

extern "C" {
#include "linux_includes/bpf.h"
}

namespace katran {

constexpr int BPF_TC_INGRESS = 0xfffffff2;
constexpr int BPF_TC_EGRESS = 0xfffffff3;

// from bpf.h (list could be outdated)
constexpr unsigned int kBpfMapTypeUnspec = 0;
constexpr unsigned int kBpfMapTypeHash = 1;
constexpr unsigned int kBpfMapTypeArray = 2;
constexpr unsigned int kBpfMapTypeProgArray = 3;
constexpr unsigned int kBpfMapTypePerfEventArray = 4;
constexpr unsigned int kBpfMapTypePercpuHash = 5;
constexpr unsigned int kBpfMapTypePercpuArray = 6;
constexpr unsigned int kBpfMapTypeStackTrace = 7;
constexpr unsigned int kBpfMapTypeCgroupArray = 8;
constexpr unsigned int kBpfMapTypeLruHash = 9;
constexpr unsigned int kBpfMapTypeLruPercpuHash = 10;
constexpr unsigned int kBpfMapTypeLpmTrie = 11;
constexpr unsigned int kBpfMapTypeArrayOfMaps = 12;
constexpr unsigned int kBpfMapTypeHashOfMaps = 13;

/**
 * This class implements API to work with bpf programs (such as load program,
 * update/lookup maps etc), as well as some helper functions (resolve ifindex).
 * This class is not thread safe.
 */
class BpfAdapter {
 public:
  explicit BpfAdapter(bool set_limits = true);

  // BpfAdapter is not thread safe.  Discourage unsafe use by disabling copy
  // construction/assignment.
  BpfAdapter(BpfAdapter const&) = delete;
  BpfAdapter& operator=(BpfAdapter const&) = delete;

  /**
   * @param string bpf_prog path to bpf program
   * @param bpf_prog_type type of bpf prog to load
   * @return int result 0 in case of success, other val otherwise
   *
   * helper function to load bpf program into the kernel
   * loader could either deduct type from prog's name
   * (supported xdp- and cls- prefixes) or by using option
   * bpf_prog_type hint
   */
  int loadBpfProg(
      const std::string& bpf_prog,
      const bpf_prog_type type = BPF_PROG_TYPE_UNSPEC);

  /**
   * @param string name of the map (as in bpf's .c file)
   * @return int bpf's map descriptor
   *
   * helper function which return's map descriptor for map
   * w/ specified name
   * on error return's -1
   */
  int getMapFdByName(const std::string& name);

  /**
   * @param unsigned int type of map to create
   * @param unsigned int key_size size of the key in a map
   * @param unsigned int value_size size of the map's value
   * @param unsigned int max_entries maximum entries in the map
   * @param unsigned int map_flags map's specific flags
   * @param int numa_node where mem is going to be allocated
   * @return int -1 on error, map's fd otherwise
   *
   * cpp wrapper around bpf_create_map helper
   * current list of map types could be retrieved from bph.h
   * some common types are specified as constants in this header.
   * default behavior for numa_node is to allocate mem on the
   * same node as userspace process is running.
   */
  int createBpfMap(
      unsigned int type,
      unsigned int key_size,
      unsigned int value_size,
      unsigned int max_entries,
      unsigned int map_flags,
      int numa_node = -1);

  /**
   * @param string name of the map
   * @param unsigned int type of map to create
   * @param unsigned int key_size size of the key in a map
   * @param unsigned int value_size size of the map's value
   * @param unsigned int max_entries maximum entries in the map
   * @param unsigned int map_flags map's specific flags
   * @param int numa_node where mem is going to be allocated
   * @return int -1 on error, map's fd otherwise
   *
   * cpp wrapper around bpf_create_map_name helper
   * current list of map types could be retrieved from bph.h
   * some common types are specified as constants in this header.
   * default behavior for numa_node is to allocate mem on the
   * same node as userspace process is running.
   */
  int createNamedBpfMap(
      const std::string& name,
      unsigned int type,
      unsigned int key_size,
      unsigned int value_size,
      unsigned int max_entries,
      unsigned int map_flags,
      int numa_node = -1);

  /**
   * @param int pos index/position to update
   * @param int map_fd fd of the prototype map
   * @return 0 on success, -1 on failure
   *
   * helper function to update array of inner map's prototypes.
   * (this array is being used by map-in-map map's types)
   */
  int updateInnerMapsArray(int pos, int map_fd);

  /**
   * @param string name of the prog's section (as SEC("name") in bpf)
   * @return int bpf's prog descriptor
   *
   * helper function which returns program's descriptor for prog
   * which section's name is equal to specified one
   * on error returns -1
   */
  int getProgFdByName(const std::string& name);

  /**
   * @param int fd of the object (e.g. map)
   * @param string path where we want our obj to pin
   * @return int 0 on success; non-zero othewise
   *
   * helper function to pin bpf's object to specified location
   */
  static int pinBpfObject(int fd, const std::string& path);

  /**
   * @param string path where bpf's obj is pinned to
   * @return fd on success; negative on failure
   *
   * helper function to get fd of pinned bpf's object
   */
  static int getPinnedBpfObject(const std::string& path);

  /**
   * @param const string& interface name
   * @return int interface index, or 0 if interface can't be found
   *
   * helper function to resolve interface name to interface index
   */
  static int getInterfaceIndex(const std::string& interface_name);

  /**
   * @param int prog_fd descriptor of the program
   * @param const string& interface name
   * @param int direction ingress or egress
   * @param const string& name of bpf program (will be visiable in tc output)
   * @return int 0 on success, other val otherwise
   *
   * helper function which attach bpf program to tc's hook
   * on specified interface in specified direction
   */
  int attachBpfProgToTc(
      const int prog_fd,
      const std::string& interface_name,
      const int direction = BPF_TC_INGRESS,
      const std::string& bpf_name = "tc-bpf",
      const uint32_t priority = 2307);

  /**
   *  @param int prog_fd descriptor of the program
   *  @param string interface_name to attach
   *  @return int 0 on success
   *
   *  helper function to attach bpf prog to specified interface
   */
  int attachXdpProg(const int prog_fd, const std::string& interface_name);

  /**
   * @param string interface_name from which we want to detach xdp prog
   * @return int 0 on success
   *
   * helper function to detach bpf prog from interface
   */
  int detachXdpProg(const std::string& interface_name);

  /**
   * @param int interface ifindex
   * @return int 0 on success
   *
   * helper function to detach bpf prog from interface w/ specified index
   */
  int detachXdpProg(const int ifindex);

  /**
   * @param int map_fd file descriptor of map to update
   * @param void* key pointer to map's key which value we want to update
   * @param void* value pointer to new value
   * @param usinged long long flags
   * @return int 0 on success, other val otherwise
   *
   * helper function to update (and/or create; depends on container)
   * value inside bpf map
   */
  int bpfUpdateMap(
      int map_fd,
      void* key,
      void* value,
      unsigned long long flags = 0);

  /**
   * @param int map_fd file descriptor of map to update
   * @param void* key pointer to map's key which value we want to get
   * @param void* value pointer where we will write value from map
   * @return int 0 on success, other val otherwise
   *
   * helper function to update (and/or create; depends on container)
   * value inside bpf map
   */
  int bpfMapLookupElement(int map_fd, void* key, void* value);

  /**
   * @param int map_fd file descriptor of bpf map
   * @param void* key pointer to key, which we are going to delete
   * @return int 0 on sucess, other val otherwise
   *
   * helper function to delete element for bpf map, which key is equal to *key
   */
  int bpfMapDeleteElement(int map_fd, void* key);

  /**
   * @param int map_fd file descriptor of bpf map
   * @param void* key pointer to key, void* next_key pointer to the next key
   * @return int 0 on success, -1 or otherval otherwise
   *
   * helper function to iterate through the keys of a map
   */
  int bpfMapGetNextKey(int map_fd, void* key, void* next_key);

  /**
   * @param int prog_fd descriptor of bpf program
   * @param unsigned int ifindex - index of the interface
   * @param const string& bpf_name name of program
   * @param uint32_t& priority priority of tc's filter
   * @return int 0 on success, other val otherwise
   *
   * helper function to attach bpf to specified interface (thru ifindex)
   * and w/ specified priority. if there is already filter w/ specified
   * priority, this call will fails (return non 0);
   */
  int addTcBpfFilter(
      const int prog_fd,
      const unsigned int ifindex,
      const std::string& bpf_name,
      uint32_t priority,
      const int direction = BPF_TC_INGRESS);

  /**
   *  @param int prog_fd descriptor of the program
   *  @param usigned int ifindex of interface
   *  @param uint32_t flags optional xdp flags
   *  @return int 0 on success
   *
   *  helper function to add or delete (by specifying prog_fd = -1) xdp
   *  prog
   */
  int modifyXdpProg(
      const int prog_fd,
      const unsigned int ifindex,
      const uint32_t flags = 0);

  /**
   * @param int prog_fd descriptor of bpf program
   * @param unsigned int ifindex - index of the interface
   * @param const string& bpf_name name of program
   * @param uint32_t& priority priority of tc's filter
   * @return int 0 on success, other val otherwise
   *
   * helper function to replace bpf filter on specified interface
   * (thru ifindex) and w/ specified priority. if there is no filter
   * with specified priority this call will create a new one
   */
  int replaceTcBpfFilter(
      const int prog_fd,
      const unsigned int ifindex,
      const std::string& bpf_name,
      const uint32_t priority,
      const int direction = BPF_TC_INGRESS);

  /**
   * @param int prog_fd descriptor of bpf program
   * @param unsigned int ifindex - index of the interface
   * @param const string& bpf_name name of program
   * @param uint32_t& priority priority of tc's filter
   * @return int 0 on success, other val otherwise
   *
   * helper function to delete bpf prog (filter) from specified interface.
   * to delete specified filter priority must be specified
   */
  int deleteTcBpfFilter(
      const int prog_fd,
      const unsigned int ifindex,
      const std::string& bpf_name,
      const uint32_t priority,
      const int direction = BPF_TC_INGRESS);

  /**
   * @param int prog_fd descriptor of bpf program
   * @param int repeat how many times repeat a test run
   * @param void* data pointer to the input packet
   * @param uint32_t data_size size of the packet
   * @param void* data_out pointer to the output (where we store a result)
   * @param uint32_t* size_out size of the output packet. optional
   * @param uint32_t* retval return value of the program
   * @param uint32_t* duration how long did it take to run a test
   * @return int result of the test. 0 on success, non 0 otherwise
   *
   * helper function which allow user to test xdp program by specifying
   * program_fd and input value (ptr to packet and it's size)
   * it will return modified (if program modifies it) packet
   * and xdp's return code.
   */
  int testXdpProg(
      const int prog_fd,
      const int repeat,
      void* data,
      uint32_t data_size,
      void* data_out,
      uint32_t* size_out = nullptr,
      uint32_t* retval = nullptr,
      uint32_t* duration = nullptr);

  /**
   * @param int prog_fd descriptor of the program
   * @param string path to cgroup directory
   * @param enum bpf_attach_type type of attachment
   * @param unsigned int flags
   * @return int 0 on success, non 0 otherwise
   *
   * helper function to attach bpf prog to specified cgroup
   */
  int attachCgroupProg(
      int prog_fd,
      const std::string& cgroup,
      enum bpf_attach_type type,
      unsigned int flags);

  /**
   * @param string path to cgroup directory
   * @param enum bpf_attach_type type of attachment
   * @return int 0 on success, non 0 otherwise
   *
   * helper function to detach all bpf progs from specified cgroup
   */
  int detachCgroupProg(const std::string& cgroup, enum bpf_attach_type type);

  /**
   * @param int bpf prog fd
   * @param string path to cgroup directory
   * @param enum bpf_attach_type type of attachment
   * @return int 0 on success, non 0 otherwise
   *
   * helper function to detach specified (by fd) bpf progs
   * from specified cgroup
   */
  int detachCgroupProg(
      int prog_fd,
      const std::string& cgroup,
      enum bpf_attach_type type);

 private:
  /**
   * helper function to modify (add/delete/replace) tc's bpf prog.
   * this is lowlvl function which would be used by all other public wrappers
   */
  int modifyTcBpfFilter(
      const int cmd,
      const unsigned int flags,
      const uint32_t priority,
      const int prog_fd,
      const unsigned int ifindex,
      const std::string& bpf_name,
      const int direction = BPF_TC_INGRESS);

  /**
   * Generic wrapper to add bpf prog to tc.
   */
  int genericAttachBpfProgToTc(
      const int prog_fd,
      const unsigned int ifindex,
      const std::string& bpf_name,
      uint32_t priority,
      const int direction = BPF_TC_INGRESS);

  /**
   * helper function which open specified dir and returns it's fd.
   * used to get cgroup's fd from path
   * returns -1 on failure
   */
  int getDirFd(const std::string& path);

  /**
   * object file loader
   */
  BpfLoader loader_;
};

} // namespace katran
