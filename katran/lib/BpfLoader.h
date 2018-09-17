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
#include <vector>

extern "C" {
#include <gelf.h>
#include <libelf.h>
#include "linux_includes/bpf.h"
}

#include "BpfLoaderStructs.h"

namespace katran {

/**
 * This is a helper class which implements routines to load a bpf program
 * from object file into kernel.
 */
class BpfLoader {
 public:
  BpfLoader();

  ~BpfLoader();

  /**
   * @param char* ptr to buffer with elf object
   * @param int size of the buffer with elf object
   * @param bpf_prog_type type of bpf program to load.
   * @return int 0 on success
   *
   * helper function to load bpf program from specified buffer (in elf format).
   * for XDP and TC bpf programs we could
   * deduce the type from program's name (if they starts with xdp or cls)
   * could throw if object buffer is malformed.
   */
  int loadBpfFromBuffer(
      char* buf,
      int buf_size,
      const bpf_prog_type type = BPF_PROG_TYPE_UNSPEC);

  /**
   * @param string path to bpf object file
   * @param bpf_prog_type type of bpf program to load.
   * @return int 0 on success
   *
   * helper function to load bpf program. for XDP and TC bpf programs we could
   * deduce the type from program's name (if they starts with xdp or cls)
   * could throw if object file is malformed.
   */
  int loadBpfFile(
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
   * @param int pos position in innerMap's array of specified prototype
   * @param int mapFd descriptor of prototype for map-in-map
   * @return int 0 on success
   *
   * helper function to load prototype for map-in-map
   */
  int updateInnerMapsArray(int pos, int mapFd);

  /**
   * @param string name of the bpf program
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
   * helper function which parse section of elf file. return 0 on success
   */
  int getSection(
      Elf* elf,
      int index,
      char** shname,
      GElf_Shdr* shdr,
      Elf_Data** data);

  /**
   * helper function to load maps.
   */
  int loadMaps(Elf* elf);

  /**
   * helper function which creates mapping between offset in map's section
   * and map's name
   */
  void loadStrings(std::unordered_map<uint32_t, uint32_t>& symbols, Elf* elf);

  /**
   * helper function which creates mapping between offset in map's section
   * and position of map's name in elf's strtab section. after that
   * it runs loadString helper.
   */
  void loadSymbols(Elf* elf);

  /**
   * helper function which laod bpf's code in kernel.
   */
  int loadAndAttach(
      const std::string& progName,
      const std::string& progPrefix,
      struct bpf_insn* prog,
      int size);

  /**
   * helper function to load bpf programs
   */
  int loadBpfProgs();

  /**
   * helper function to parse elf and load bpf program from it
   */
  int parseElf(const std::string& name);

  /**
   * helper function to initialize scratch/tmp variables
   */
  void initializeTempVars();

  /**
   * helper function to collect indexes for maps/strings/symbols/text sections
   * and populate kernel and license data
   */
  int collectElfData(const std::string& name);

  /**
   * helper function to add prog data
   */
  int addProgData(const std::string& name, Elf_Data* data, int idx);

  /**
   * helper function to collect relocation data for programs
   */
  int collectReloc();

  /**
   * helper function to apply instruction related relocations for the programs
   */
  int relocateInsns();

  /**
   * helper function to apply map's related rellocations for the programs
   */
  int relocateMaps();

  /**
   * helper function to clear/free malloc'd memory associated with instructions
   * in BpfProgData
   */
  void freeBpfProgDataInsns(BpfProgData& prog);

  /**
   * helper function to clear the contents of the map and also clear/free
   * malloc'd memory associated with BpfProgData in the map
   */
  void clearBpfProgDataMap();

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
   * vector of descriptor's for map-in-map prototypes.
   */
  std::vector<int> innerMapsProto_;

  /**
   * counter of how many bpf progs has been loaded. current limit
   * (could be changed) is 32
   */
  uint32_t progsCntr_{0};

  /**
   * counter of how many bpf's maps has been loaded. current limit is 32.
   */
  uint32_t mapsCntr_{0};

  /**
   * all variables bellow are temporary and used as scratch objects
   * they are valid only during loadBpfFile run.
   */

  /**
   * tmp string which holds license type of last loaded bpf file.
   */
  std::string license_;

  /**
   * tmp int which holds kernel's version restriction of last loaded bpf file.
   */
  int kernelVersion_{0};

  /**
   * tmp variable which holds bpf prog type of last loaded bpf file
   */
  bpf_prog_type progType_{BPF_PROG_TYPE_UNSPEC};

  /**
   * tmp pointer to elf descriptor
   */
  Elf* elf_;

  /**
   * tmp pointer to symbol table
   */
  Elf_Data* symbolTable_;

  /**
   * tmp storage for elf header
   */
  GElf_Ehdr ehdr_;

  /**
   * tmp vector which contains indexes of map/symbol/string/text sections
   */
  std::vector<int> sectionsIndexes_;

  /**
   * tmp vector w/ rellocation data
   */
  std::vector<RelocData> relocs_;

  /**
   * tmp map w/ section index to bpf prog ralated data mappings
   */
  std::unordered_map<int, BpfProgData> progsData_;

  /**
   * tmp object w/ map's offset to name mapping
   */
  std::unordered_map<uint32_t, std::string> offsetToMap_;
};

} // namespace katran
