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
#include <folly/Function.h>
#include <string>
#include <unordered_map>
#include <vector>

#include "BpfLoader.h"

extern "C" {
#include <bpf/bpf.h>
#include <linux/perf_event.h>
}

namespace katran {

constexpr int TC_INGRESS = 0xfffffff2;
constexpr int TC_EGRESS = 0xfffffff3;

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
   * @param bool use_names flag to mark if names for maps/progs should be loaded
   * @return int result 0 in case of success, other val otherwise
   *
   * helper function to load bpf program into the kernel
   * loader could either deduct type from prog's name
   * (supported xdp- and cls- prefixes) or by using option
   * bpf_prog_type hint
   */
  int loadBpfProg(
      const std::string& bpf_prog,
      const bpf_prog_type type = BPF_PROG_TYPE_UNSPEC,
      bool use_names = false);

  /**
   * @param string bpf_prog path to bpf program
   * @param bpf_prog_type type of bpf prog to load
   * @return int result 0 in case of success, other val otherwise
   *
   * helper function to reload bpf program into the kernel
   * loader could either deduct type from prog's name
   * (supported xdp- and cls- prefixes) or by using option
   * bpf_prog_type hint
   */
  int reloadBpfProg(
      const std::string& bpf_prog,
      const bpf_prog_type type = BPF_PROG_TYPE_UNSPEC);

  /**
   * @param char* ptr to buffer with bpf's elf object
   * @param int size of the buffer
   * @param bpf_prog_type type of bpf prog to load
   * @param bool use_names flag to mark if names for maps/progs should be loaded
   * @return int result 0 in case of success, other val otherwise
   *
   * helper function to load bpf program into the kernel from buffer
   * loader could either deduct type from prog's name
   * (supported xdp- and cls- prefixes) or by using option
   * bpf_prog_type hint
   */
  int loadBpfProg(
      char* buf,
      int buf_size,
      const bpf_prog_type type = BPF_PROG_TYPE_UNSPEC,
      bool use_names = false);

  /**
   * @param string name of the map (as in bpf's .c file)
   * @return int bpf's map descriptor
   *
   * helper function which return's map descriptor for map
   * w/ specified name
   * on error return's -1
   * note: positive return value doesn't mean map is in the current prog, just
   * that it's opened
   */
  int getMapFdByName(const std::string& name);

  /**
   * @param string name of the prog
   * @param string name of the map (as in bpf's .c file)
   * @return bool whether the map is present in the current prog
   *
   * helper function to check if a map is in current prog
   */
  bool isMapInProg(const std::string& progName, const std::string& name);

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
  static int createBpfMap(
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
  static int createNamedBpfMap(
      const std::string& name,
      unsigned int type,
      unsigned int key_size,
      unsigned int value_size,
      unsigned int max_entries,
      unsigned int map_flags,
      int numa_node = -1);

  /**
   * @param string name of map-in-map w/ specified fd as prototype
   * @param int map_fd fd of the prototype map
   * @return 0 on success, -1 on failure
   *
   * helper function to set prototype for map-in-map
   */
  int setInnerMapPrototype(const std::string& name, int map_fd);

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
   * @param int fd of the object (e.g. map)
   * @param bpf_map_info* pointer of pre-allocated bpf map info to populate
   * @return int 0 on success; non-zero otherwise
   *
   * helper function to get the metadata of a bpf map
   */
  static int getBpfMapInfo(const int& fd, struct bpf_map_info* info);

  /**
   * @param string name of the bpf map
   * @return int >=0 on success; negative on failure
   *
   * helper function to get the max number of entries in a bpf map
   */
  int getBpfMapMaxSize(const std::string& name);

  /**
   * @param string name of the bpf map
   * @return int >=0 on success; negative on failure
   *
   * helper function to get the current number of entries in a bpf map
   * O(N) on the map size -- this walks every key in the map
   */
  int getBpfMapUsedSize(const std::string& name);

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
  static int attachBpfProgToTc(
      const int prog_fd,
      const std::string& interface_name,
      const int direction = TC_INGRESS,
      const std::string& bpf_name = "tc-bpf",
      const uint32_t priority = 2307);

  /**
   *  @param int prog_fd descriptor of the program
   *  @param string interface_name to attach
   *  @param uint32_t flags xdp flags for attaching xdp prog. 0 is default
   *  @return int 0 on success
   *
   *  helper function to attach bpf prog to specified interface
   */
  static int attachXdpProg(
      const int prog_fd,
      const std::string& interface_name,
      const uint32_t flags = 0);

  /**
   * @param string interface_name from which we want to detach xdp prog
   * @param uint32_t flags xdp flags used for attaching xdp prog. 0 is default
   * @return int 0 on success
   *
   * helper function to detach bpf prog from interface
   */
  static int detachXdpProg(
      const std::string& interface_name,
      const uint32_t flags = 0);

  /**
   * @param int interface ifindex
   * @param uint32_t flags xdp flags used for attaching xdp prog. 0 is default
   * @return int 0 on success
   *
   * helper function to detach bpf prog from interface w/ specified index
   */
  static int detachXdpProg(const int ifindex, const uint32_t flags = 0);

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
  static int bpfUpdateMap(
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
  static int bpfMapLookupElement(int map_fd, void* key, void* value);

  /**
   * @param int map_fd file descriptor of bpf map
   * @param void* key pointer to key, which we are going to delete
   * @return int 0 on sucess, other val otherwise
   *
   * helper function to delete element for bpf map, which key is equal to *key
   */
  static int bpfMapDeleteElement(int map_fd, void* key);

  /**
   * @param int map_fd file descriptor of bpf map
   * @param void* key pointer to key, void* next_key pointer to the next key
   * @return int 0 on success, -1 or otherval otherwise
   *
   * helper function to iterate through the keys of a map
   */
  static int bpfMapGetNextKey(int map_fd, void* key, void* next_key);

  /**
   * @param int outer_map_fd file descriptor of the map-in-map
   * @param void* key pointer to the key, for looking up the associated value
   * @return int fd of inner map on success, -1 on failure
   *
   * Returns FD of the inner bpf map associated with the given
   * key in the given map-in-map with fd=outer_map_fd
   *
   * NOTE: bpf internally increments the reference count of the inner map after
   * successfully looking up by it's id. Thus, the userspace program
   * must close the FD to avoid leaks.
   */
  static int bpfMapGetFdOfInnerMap(int outer_map_fd, void* key);

  /**
   * @param uint32_t map_id valid id of a bpf map
   * @return int fd of the map if success, -1 on failure
   *
   * Given id of a bpf map, returns it's file descriptor (fd)
   *
   * NOTE: bpf internally increments the reference count of the map after
   * successfully looking up by it's id. Thus, the userspace program
   * must close the FD to avoid leaks.
   */
  static int bpfMapGetFdById(uint32_t map_id);

  /**
   * @param uint32_t prog_id valid id of a bpf prog
   * @return int fd of the prog if success, -1 on failure
   *
   * Given id of a bpf prog, returns it's file descriptor (fd)
   *
   * NOTE: bpf internally increments the reference count of the prog after
   * successfully looking up by it's id. Thus, the userspace program
   * must close the FD to avoid leaks.
   */
  static int bpfProgGetFdById(uint32_t prog_id);

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
  static int addTcBpfFilter(
      const int prog_fd,
      const unsigned int ifindex,
      const std::string& bpf_name,
      uint32_t priority,
      const int direction = TC_INGRESS);

  /**
   *  @param int prog_fd descriptor of the program
   *  @param usigned int ifindex of interface
   *  @param uint32_t flags optional xdp flags
   *  @return int 0 on success
   *
   *  helper function to add or delete (by specifying prog_fd = -1) xdp
   *  prog
   */
  static int modifyXdpProg(
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
  static int replaceTcBpfFilter(
      const int prog_fd,
      const unsigned int ifindex,
      const std::string& bpf_name,
      const uint32_t priority,
      const int direction = TC_INGRESS);

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
  static int deleteTcBpfFilter(
      const int prog_fd,
      const unsigned int ifindex,
      const std::string& bpf_name,
      const uint32_t priority,
      const int direction = TC_INGRESS);

  /**
   * @param int prog_fd descriptor of bpf program
   * @param int repeat how many times repeat a test run
   * @param void* data pointer to the input packet
   * @param uint32_t data_size size of the packet
   * @param void* data_out pointer to the output (where we store a result)
   * @param uint32_t* size_out size of the output packet. optional
   * @param uint32_t* retval return value of the program
   * @param uint32_t* duration how long did it take to run a test
   * @param void* ctx_in optional pointer to context
   * @param uint32_t ctx_size_in size of the context
   * @param void* ctx_out optional pointer to output context
   * @param uint32_t* ctx_size_out pointer to the size of ctx after test run
   * @return int result of the test. 0 on success, non 0 otherwise
   *
   * helper function which allow user to test xdp program by specifying
   * program_fd and input value (ptr to packet and it's size)
   * it will return modified (if program modifies it) packet
   * and xdp's return code.
   */
  static int testXdpProg(
      const int prog_fd,
      const int repeat,
      void* data,
      uint32_t data_size,
      void* data_out,
      uint32_t* size_out = nullptr,
      uint32_t* retval = nullptr,
      uint32_t* duration = nullptr,
      void* ctx_in = nullptr,
      uint32_t ctx_size_in = 0,
      void* ctx_out = nullptr,
      uint32_t* ctx_size_out = nullptr);

  /**
   * @param int prog_fd descriptor of the program
   * @param string path to cgroup directory
   * @param enum bpf_attach_type type of attachment
   * @param unsigned int flags
   * @return int 0 on success, non 0 otherwise
   *
   * helper function to attach bpf prog to specified cgroup
   */
  static int attachCgroupProg(
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
  static int detachCgroupProg(
      const std::string& cgroup,
      enum bpf_attach_type type);

  /**
   * @param string path to cgroup directory
   * @param enum bpf_attach_type type of attachment
   * @param string progPrefix Prefix to match with each bpf-program name in
   *        the specified group before detaching the program
   * @return int 0 on success, non 0 otherwise
   *
   * helper function to detach all bpf progs with matching program name
   * prefix from specified cgroup
   */
  static int detachCgroupProgByPrefix(
      const std::string& cgroup,
      enum bpf_attach_type type,
      const std::string& progPrefix);

  /**
   * @param int bpf prog fd
   * @param string path to cgroup directory
   * @param enum bpf_attach_type type of attachment
   * @return int 0 on success, non 0 otherwise
   *
   * helper function to detach specified (by fd) bpf progs
   * from specified cgroup
   */
  static int detachCgroupProg(
      int prog_fd,
      const std::string& cgroup,
      enum bpf_attach_type type);

  /**
   * @param string path to cgroup directory
   * @param enum bpf_attach_type type of attachment
   * @return vector int of fds of attached bpf progs
   *
   * helper function to get a list of fds of all attached bpf progs
   * with specified type to specified cgroup
   */
  static std::vector<uint32_t> getCgroupProgsIds(
      const std::string& cgroup,
      enum bpf_attach_type type);

  /**
   * @param int Fd of a valid bpf program
   * @param bpf_prog_info info object to be populated with result
   * @return 0 if successful
   *
   * helper function to get info about a valid bpf program
   */
  static int getBpfProgInfo(int progFd, ::bpf_prog_info& info);

  /**
   * @param int Fd of a valid bpf program
   * @return bpf_prog_info object with info about the given program
   * @throws std::runtime_exception on error
   *
   * helper function to get info about a valid bpf program
   */
  static bpf_prog_info getBpfProgInfo(int progFd);

  /**
   * @param string name of the shared map
   * @param int fd of the shared map
   * @return 0 on success
   *
   * helper function to update shared map's dictionary
   */
  int updateSharedMap(const std::string& name, int fd);

  /**
   * @return number of possible cpus used for percpu maps
   *
   * helper function which retrieves number of cpus which have allocated
   * resources in running system. return -1 on failure, number of CPUs
   * otherwise.
   */
  static int getPossibleCpus();

  /**
   * @return number of online cpus in the system
   *
   * helper function which retrieves number of currently online cpus.
   * return -1 on failure, number of CPUs
   * otherwise.
   */
  static int getOnlineCpus();

  /**
   * @param struct perf_event_mmap_page* header ptr to mmaped memory
   * @param int pages size of mmap region in pages
   * @return true on success
   *
   * helper function to unmap previously mmaped pages for bpf_perf_event
   */
  static bool perfEventUnmmap(struct perf_event_mmap_page** header, int pages);

  /**
   * @param int cpu where perf event needs to be attached
   * @param int map_fd descriptor of bpf's perf event map
   * @param int wakeUpNumEvents sampling rate. wake up every wakeUpNumEvents
   * @param struct perf_event_mmap_page** header of mmaped memory region
   * @param int& event_fd descriptor of new perf event
   * @return true on success
   *
   * helper function to mmap memory region and create a new perf event which is
   * going to use it on specified cpu w/ specified sampling rate.
   * header and event_fd params are going to be used to store allocated values
   */
  static bool openPerfEvent(
      /* input */
      int cpu,
      int map_fd,
      int wakeUpNumEvents,
      int pages,
      /* output */
      struct perf_event_mmap_page** header,
      int& event_fd);

  /**
   * @param Function eventHandler cb to run on received perf event
   * @param perf_event_mmap_page header ptr to mmape memory region of perf event
   * @param string& buffer to copy perf event data to
   * @param int pageSize size of a single page
   * @param int pages size in pages of mmaped memory region
   * @param int cpu cpu to get handle event from
   *
   * helper function to handle perf event from specified cpu
   * and call specified helper
   */
  static void handlePerfEvent(
      folly::Function<void(const char* data, size_t size)> eventHandler,
      struct perf_event_mmap_page* header,
      std::string& buffer,
      int pageSize,
      int pages,
      int cpu);

  /**
   * @param path path to the .o object file
   * @param mapName name of map to check
   *
   * stateless helper function to check for the presence of a map in an
   * unloaded bpf file
   */
  static bool isMapInBpfObject(
    const std::string& path,
    const std::string& mapName);

 private:
  /**
   * helper function to modify (add/delete/replace) tc's bpf prog.
   * this is lowlvl function which would be used by all other public wrappers
   */
  static int modifyTcBpfFilter(
      const int cmd,
      const unsigned int flags,
      const uint32_t priority,
      const int prog_fd,
      const unsigned int ifindex,
      const std::string& bpf_name,
      const int direction = TC_INGRESS);

  /**
   * helper function to add clsact qdisk to interface for healthchecking
   */
  static int addClsActQD(const unsigned int ifindex);

  /**
   * Generic wrapper to add bpf prog to tc.
   */
  static int genericAttachBpfProgToTc(
      const int prog_fd,
      const unsigned int ifindex,
      const std::string& bpf_name,
      uint32_t priority,
      const int direction = TC_INGRESS);

  /**
   * helper function which open specified dir and returns it's fd.
   * used to get cgroup's fd from path
   * returns -1 on failure
   */
  static int getDirFd(const std::string& path);

  /**
   * helper function to mmap pages for bpf_perf_event
   */
  static struct perf_event_mmap_page* perfEventMmap(int event_fd, int pages);

  /**
   * object file loader
   */
  BpfLoader loader_;
};

} // namespace katran
