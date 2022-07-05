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

#include <set>
#include <string>
#include <unordered_map>

extern "C" {
#include <bpf/libbpf.h>
}

namespace katran {

/**
 * This is a helper class which implements routines to load a bpf program
 * from object file into kernel.
 */
class BpfLoader {
 public:
  explicit BpfLoader();

  ~BpfLoader();

  /**
   * @param char* ptr to buffer with elf object
   * @param int size of the buffer with elf object
   * @param bpf_prog_type type of bpf program to load.
   * @param bool use_names flag to mark if names for maps/progs should be loaded
   * @return int 0 on success
   *
   * helper function to load bpf program from specified buffer (in elf format).
   * for XDP and TC bpf programs we could
   * deduce the type from program's name (if they starts with xdp or cls)
   * could throw if object buffer is malformed.
   */
  int loadBpfFromBuffer(
      const char* buf,
      int buf_size,
      const bpf_prog_type type = BPF_PROG_TYPE_UNSPEC,
      bool use_names = false,
      const char* objName = "buffer");

  /**
   * @param string path to bpf object file
   * @param bpf_prog_type type of bpf program to load.
   * @param bool use_names flag to mark if names for maps/progs should be loaded
   * @return int 0 on success
   *
   * helper function to load bpf program. for XDP and TC bpf programs we could
   * deduce the type from program's name (if they starts with xdp or cls)
   * could throw if object file is malformed.
   */
  int loadBpfFile(
      const std::string& path,
      const bpf_prog_type type = BPF_PROG_TYPE_UNSPEC,
      bool use_names = false);

  /**
   * @param string path to bpf object file
   * @param bpf_prog_type type of bpf program to load.
   * @return int 0 on success
   *
   * helper function to reload bpf program. for XDP and TC bpf programs we could
   * deduce the type from program's name (if they starts with xdp or cls)
   * could throw if object file is malformed
   */
  int reloadBpfFromFile(
      const std::string& path,
      const bpf_prog_type type = BPF_PROG_TYPE_UNSPEC);

  /**
   * @param string name of the map
   * @return int negative on failure, map's fd on success
   *
   * helper function to get map's fd (if map is loaded)
   */
  int getMapFdByName(const std::string& name);

  /**
   * @param string name of the prog
   * @param string name of the map
   * @return bool true if the map is present in current prog, otherwise false
   *
   * helper function to check if a map is in current prog
   */
  bool isMapInProg(const std::string& progName, const std::string& name);

  /**
   * @param string name of map-in-map which is going to use fd as prototype
   * @param int mapFd descriptor of prototype for map-in-map
   * @return int 0 on success
   *
   * helper function to set prototype for map-in-map w/ specified name
   */
  int setInnerMapPrototype(const std::string& name, int fd);

  /**
   * @param string name of the bpf program (function name)
   * @return int negative on failure, prog's fd on success
   *
   * helper function to get program's descriptor
   */
  int getProgFdByName(const std::string& name);

  /**
   * @param string name of the shared map
   * @param int fd descriptor of the shared map
   * @return int 0 on success
   *
   * helper function to update/specify shared map's descriptor
   */
  int updateSharedMap(const std::string& name, int fd);

 private:
  /**
   * helper function to load bpf object
   */
  int loadBpfObject(
      ::bpf_object* obj,
      const std::string& objName,
      const bpf_prog_type type = BPF_PROG_TYPE_UNSPEC);

  /**
   * helper function to reload bpf object
   */
  int reloadBpfObject(
      ::bpf_object* obj,
      const std::string& objName,
      const bpf_prog_type type = BPF_PROG_TYPE_UNSPEC);

  /**
   * helper function to close bpf object and return error.
   */
  int closeBpfObject(::bpf_object* obj);

  const char* getProgNameFromBpfProg(const struct bpf_program* prog);

  /**
   * dict of path to bpf objects mapping
   */
  std::unordered_map<std::string, ::bpf_object*> bpfObjects_;
  /**
   * dict of map's name to map's descriptor mappings
   */
  std::unordered_map<std::string, int> maps_;

  /**
   * dict of prog's name to descriptor mappings.
   */
  std::unordered_map<std::string, int> progs_;

  /**
   * dict of shared map's name to descriptor mappings.
   */
  std::unordered_map<std::string, int> sharedMaps_;

  /**
   * map of prototypes for inner map.
   */
  std::unordered_map<std::string, int> innerMapsProto_;

  /**
   * Set of maps present in the *current* prog, which is a subset of maps_
   */
  std::unordered_map<std::string, std::set<std::string>> currentMaps_;

  /**
   * Set of known duplicate maps that cause conflicts on bpf loading
   * Some maps are autogenerated https://github.com/libbpf/libbpf/issues/274
   * TODO: may need to change to prefix match in future
   */
  const std::set<std::string> knownDuplicateMaps_ = {".rodata.str1.1"};
};

} // namespace katran
