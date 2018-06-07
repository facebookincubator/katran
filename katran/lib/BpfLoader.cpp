/*
 * Copyright 2004-present Facebook. All Rights Reserved.
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
 *
 * before doing any changes in this file you must
 * have pretty solid understanding of elf's file format.
 * (https://en.wikipedia.org/wiki/Executable_and_Linkable_Format)
 *
 * brief overview of how bpf programs are loaded from elf file:
 * 1) we parse whole file and collect data about kernel/license
 * as well as indexes of sections (such as map/prog/reloc etc)
 * 2) we parse symbol and string tables section and create
 * dictionary of mappings betwen map's position in map's section
 * and map's name
 * 3) we load maps from map's section. few notes:
 * before load map we look into dictionary for it's name. we throw if
 * we wasn't able to find it's name (that means step 2 was somehow a failure)
 * after that we look into shared map's dictionary (to check if this map
 * is shared between two bpf's programs and already loaded in kernel)
 * only if it's not a shared map we do load it into kernel
 * 4) we collect relocation data for programs. (e.g. if it's a map - what fd
 * should be used, or if's function call - what is the offset)
 * 5) using relocation data from step 4 we are applying relocations for maps
 * (during compile time LLVM doesn't know actual fd of the map. instead it put
 * BPF_PSEUDO_MAP_FD as a place holder. in this step we are rewriting this
 * placeholder to actual map's fd)
 * 6) using relocation data from step 4 we are applying relocations for bpf
 * function calls (same idea as with maps)
 * 7) finaly we are loading bpf programs into kernel
 */

#include "BpfLoader.h"

#include <glog/logging.h>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>

extern "C" {
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "linux_includes/libbpf.h"
}

#include <folly/ScopeGuard.h>

namespace katran {

namespace {
constexpr int kMaxMaps = 32;
constexpr int kMaxInnerMaps = kMaxMaps;
constexpr int kMaxProgs = 32;
constexpr int kMaxSections = 128;
constexpr int kMegaByte = 1024 * 1024;
constexpr int kLogBufSize = 10 * kMegaByte;
constexpr int kNotExists = -1;
constexpr int kStart = 0;
constexpr int kPrefixSize = 3;
constexpr int kTextSection = 0;
constexpr int kMapsSection = 1;
constexpr int kSymbolSection = 2;
constexpr int kStringSection = 3;
} // namespace

BpfLoader::BpfLoader()
    : innerMapsProto_(kMaxInnerMaps, kNotExists),
      sectionsIndexes_(4, kNotExists) {}

int BpfLoader::getMapFdByName(const std::string& name) {
  auto map = maps_.find(name);
  if (map == maps_.end()) {
    LOG(ERROR) << "Can't find name w/ name: " << name;
    return kNotExists;
  } else {
    return map->second;
  }
}

int BpfLoader::updateInnerMapsArray(int pos, int mapFd) {
  if (pos < 0 || pos > kMaxInnerMaps || mapFd < 0) {
    return kNotExists;
  } else {
    innerMapsProto_[pos] = mapFd;
    return 0;
  }
}

int BpfLoader::getProgFdByName(const std::string& name) {
  auto prog = progs_.find(name);
  if (prog == progs_.end()) {
    LOG(ERROR) << "Can't find prog with name: " << name;
    return kNotExists;
  } else {
    return prog->second;
  }
}

int BpfLoader::updateSharedMap(const std::string& name, int fd) {
  auto exists = sharedMaps_.find(name);
  if (exists != sharedMaps_.end()) {
    LOG(ERROR) << "Shared maps name collision. Name: " << name;
    return kNotExists;
  } else {
    sharedMaps_[name] = fd;
    return 0;
  }
}

int BpfLoader::getSection(
    Elf* elf,
    int index,
    char** shname,
    GElf_Shdr* shdr,
    Elf_Data** data) {
  Elf_Scn* scn;

  scn = elf_getscn(elf, index);
  if (!scn) {
    LOG(ERROR) << "Can't read section for index: " << index;
    return 1;
  }

  if (gelf_getshdr(scn, shdr) != shdr) {
    LOG(ERROR) << "Can't read section header for index: " << index;
    return 1;
  }

  *shname = elf_strptr(elf, ehdr_.e_shstrndx, shdr->sh_name);

  if (!*shname) {
    LOG(ERROR) << "Can't read section name for index: " << index;
    return 1;
  }
  if (!shdr->sh_size) {
    LOG(ERROR) << "Can't read section size for index: " << index;
    return 1;
  };

  *data = elf_getdata(scn, nullptr);
  if (!*data || elf_getdata(scn, *data) != nullptr) {
    LOG(ERROR) << "Can't read section data or section contains more than one "
               << "data element. section index: " << index;
    return 1;
  }

  return 0;
}

int BpfLoader::loadMaps(Elf* elf) {
  uint32_t map_offset;
  Elf_Data* data;
  GElf_Shdr shdr;
  char* shname;
  int map_fd;

  if (getSection(elf, sectionsIndexes_[kMapsSection], &shname, &shdr, &data)) {
    LOG(ERROR) << "Can't get section for maps";
    throw std::runtime_error("error while reading maps section");
  }

  struct bpf_map_def* maps = reinterpret_cast<struct bpf_map_def*>(data->d_buf);
  int len = data->d_size;

  for (int i = 0; i < len / sizeof(struct bpf_map_def); i++) {
    if (mapsCntr_ == kMaxMaps) {
      LOG(ERROR) << "maxim ammount of maps has been reached: " << mapsCntr_;
      return 1;
    }
    map_offset = i * sizeof(struct bpf_map_def);
    auto map_symbol = offsetToMap_.find(map_offset);
    if (map_symbol == offsetToMap_.end()) {
      LOG(ERROR) << "Can't find map's name in symbol's table.";
      return 1;
    }
    auto shared_map = sharedMaps_.find(map_symbol->second);
    if (shared_map != sharedMaps_.end()) {
      VLOG(2) << "Loading shared map w/ name: " << map_symbol->second;
      maps_[map_symbol->second] = shared_map->second;
      continue;
    }
    auto exists = maps_.find(map_symbol->second);
    if (exists != maps_.end()) {
      LOG(ERROR) << "Name collision for map: " << exists->second;
      return 1;
    }
    VLOG(4) << "Loading map w/ name: " << map_symbol->second
            << " ,offset: " << map_offset;
    if (maps[i].type == BPF_MAP_TYPE_ARRAY_OF_MAPS ||
        maps[i].type == BPF_MAP_TYPE_HASH_OF_MAPS) {
      auto index = maps[i].inner_map_idx;
      if (index >= kMaxInnerMaps) {
        LOG(ERROR) << "Inner map's index is bigger then max supported"
                   << " index: " << index
                   << " max supported: " << kMaxInnerMaps;
        return 1;
      }
      int inner_map_fd = innerMapsProto_[index];
      if (inner_map_fd < 0) {
        LOG(ERROR) << "trying to use non existing map for "
                   << "map-in-map prototype";
        return 1;
      }
      map_fd = ebpf_create_map_in_map(
          static_cast<enum bpf_map_type>(maps[i].type),
          maps[i].key_size,
          inner_map_fd,
          maps[i].max_entries,
          maps[i].map_flags);
    } else {
      map_fd = ebpf_create_map(
          static_cast<enum bpf_map_type>(maps[i].type),
          maps[i].key_size,
          maps[i].value_size,
          maps[i].max_entries,
          maps[i].map_flags);
    }

    if (map_fd < 0) {
      LOG(ERROR) << "Failed to create a map. " << std::strerror(errno);
      mapsCntr_++;
      return 1;
    }
    mapsCntr_++;
    maps_[map_symbol->second] = map_fd;
  }
  return 0;
}

void BpfLoader::loadStrings(
    std::unordered_map<uint32_t, uint32_t>& symbols,
    Elf* elf) {
  char* map_name;

  for (auto& symbol : symbols) {
    map_name = elf_strptr(elf, sectionsIndexes_[kStringSection], symbol.second);
    if (map_name == nullptr) {
      throw std::runtime_error("can't get symbols name from strtab section");
    }
    offsetToMap_[symbol.first] = map_name;
  }
}

void BpfLoader::loadSymbols(Elf* elf) {
  std::unordered_map<uint32_t, uint32_t> symbols;

  Elf_Data* data;
  GElf_Shdr shdr;
  GElf_Sym sym;
  char* shname;

  // we are going to create a dict of map's offset to string's location mapping
  if (getSection(
          elf, sectionsIndexes_[kSymbolSection], &shname, &shdr, &data)) {
    // should never happens, as we already checked for exactly the same during
    // our first read of elf file while we were searching for position
    LOG(ERROR) << "Can't get section for symbols table";
    throw std::runtime_error("error while reading symtab section");
  }

  auto entries = shdr.sh_size / shdr.sh_entsize;

  for (int i = 0; i < entries; i++) {
    gelf_getsym(data, i, &sym);
    if (sym.st_shndx == sectionsIndexes_[kMapsSection]) {
      symbols[sym.st_value] = sym.st_name;
    }
  }
  symbolTable_ = data;
  return loadStrings(symbols, elf);
}

int BpfLoader::addProgData(const std::string& name, Elf_Data* data, int idx) {
  if (data->d_size < sizeof(struct bpf_insn)) {
    LOG(ERROR) << "Corrupted section " << idx;
    return 1;
  }
  if (progs_.find(name) != progs_.end()) {
    LOG(ERROR) << "Program's name collision: " << name;
    return 1;
  }
  auto size = data->d_size;
  auto insns_cnt = size / sizeof(struct bpf_insn);
  VLOG(2) << "Adding prog: " << name << " size: " << size
          << " insns: " << insns_cnt;
  BpfProgData prog;
  prog.insns = reinterpret_cast<struct bpf_insn*>(std::malloc(size));
  if (!prog.insns) {
    LOG(ERROR) << "Can not allocate memory for section " << idx;
    return 1;
  }
  prog.name = name;
  auto prog_prefix = name.substr(kStart, kPrefixSize);
  if (prog_prefix == "xdp") {
    VLOG(4) << "Prog type: XDP";
    prog.type = BPF_PROG_TYPE_XDP;
  } else if (prog_prefix == "cls") {
    VLOG(4) << "Prog type: CLS";
    prog.type = BPF_PROG_TYPE_SCHED_CLS;
  } else {
    VLOG(4) << "User specified prog type";
    prog.type = progType_;
  }
  prog.idx = idx;
  prog.insns_cnt = insns_cnt;
  prog.main_prog_cnt = 0;
  prog.size = size;
  std::memcpy(prog.insns, data->d_buf, size);
  progsData_[idx] = prog;
  return 0;
}

void BpfLoader::initializeTempVars() {
  for (auto& section : sectionsIndexes_) {
    section = kNotExists;
  }
  symbolTable_ = nullptr;
  elf_ = nullptr;
  relocs_.clear();
  progsData_.clear();
  offsetToMap_.clear();
}

int BpfLoader::collectReloc() {
  for (auto& reloc : relocs_) {
    auto idx = reloc.shdr.sh_info;
    auto prog_iter = progsData_.find(idx);
    if (prog_iter == progsData_.end()) {
      LOG(INFO) << "relocation for non existing prog w/ idx " << idx;
      continue;
    }
    VLOG(2) << "Collecting relocations for prog: " << prog_iter->second.name;
    auto insns = prog_iter->second.insns;
    auto nrels = reloc.shdr.sh_size / reloc.shdr.sh_entsize;
    for (int i = 0; i < nrels; i++) {
      GElf_Sym symbol;
      GElf_Rel relocation;
      RelocDesc rDesc;

      if (!gelf_getrel(reloc.data, i, &relocation)) {
        LOG(ERROR) << "Can't get relocation for index " << i;
        return 1;
      }

      if (!gelf_getsym(symbolTable_, GELF_R_SYM(relocation.r_info), &symbol)) {
        LOG(ERROR) << "Can't get symbol " << GELF_R_SYM(relocation.r_info)
                   << " for relocation with index " << i;
        return 1;
      }

      if ((symbol.st_shndx != sectionsIndexes_[kMapsSection]) &&
          (symbol.st_shndx != sectionsIndexes_[kTextSection])) {
        VLOG(2) << "Relocation to non prog section " << symbol.st_shndx;
        continue;
      }
      auto insn_idx = relocation.r_offset / sizeof(struct bpf_insn);

      if (insns[insn_idx].code == (BPF_JMP | BPF_CALL)) {
        if (insns[insn_idx].src_reg != BPF_PSEUDO_CALL) {
          LOG(ERROR) << "Incorrect bpf call opcode";
          return 1;
        }
        VLOG(4) << "Collecting bpf_call reloc";
        rDesc.type = RelocType::RELO_CALL;
        rDesc.insn_idx = insn_idx;
        rDesc.text_off = symbol.st_value;
        prog_iter->second.progRelocs.push_back(rDesc);
        continue;
      }

      if (insns[insn_idx].code != (BPF_LD | BPF_IMM | BPF_DW)) {
        LOG(ERROR) << "invalid relocation for instruction " << insn_idx;
        return 1;
      }

      auto map_name = offsetToMap_.find(symbol.st_value);
      if (map_name == offsetToMap_.end()) {
        LOG(ERROR) << "we are trying to rellocate non-existing map";
        return 1;
      }
      auto map_fd = maps_.find(map_name->second);
      if (map_fd == maps_.end()) {
        LOG(ERROR) << "we are trying to rellocate map which wasn't loaded";
        return 1;
      }
      VLOG(4) << "collecting relocation info for map: " << map_name->second
              << "\nfd: " << map_fd->second
              << " prog name: " << prog_iter->second.name;
      rDesc.type = RelocType::RELO_LD64;
      rDesc.insn_idx = insn_idx;
      rDesc.map_fd = map_fd->second;
      prog_iter->second.progRelocs.push_back(rDesc);
    }
  }
  return 0;
}

int BpfLoader::collectElfData(const std::string& path) {
  Elf_Data* data;
  GElf_Shdr shdr;
  char* shname;

  for (int i = 1; i < ehdr_.e_shnum; i++) {
    if (i == kMaxSections) {
      LOG(ERROR) << "Can't parse elf file. reached maximum allowed sections";
      return 1;
    }
    // scanning over all elf sections to get license and map info
    if (getSection(elf_, i, &shname, &shdr, &data)) {
      LOG(INFO) << "Skipping section: " << i << " of file: " << path;
      continue;
    }
    std::string section_name(shname);
    VLOG(4) << "section name: " << section_name << " index: " << i
            << "\ndata: " << data->d_buf << " size: " << data->d_size
            << "\nlink: " << shdr.sh_link;

    if (section_name == "license") {
      license_ = reinterpret_cast<char*>(data->d_buf);
      VLOG(2) << "license is: " << license_;
    } else if (section_name == "version") {
      if (data->d_size != sizeof(int)) {
        LOG(ERROR) << "Invalid size of version section for file: " << path;
        return 1;
      }
      kernelVersion_ = *reinterpret_cast<int*>(data->d_buf);
      VLOG(2) << "Kernel Version is: " << kernelVersion_;
    } else if (section_name == "maps") {
      sectionsIndexes_[kMapsSection] = i;
    } else if (shdr.sh_type == SHT_STRTAB) {
      sectionsIndexes_[kStringSection] = i;
    } else if (shdr.sh_type == SHT_SYMTAB) {
      sectionsIndexes_[kSymbolSection] = i;
    } else if (shdr.sh_type == SHT_REL) {
      VLOG(2) << "Pushing reloc data for section " << section_name;
      relocs_.push_back({shdr, data});
    } else if (
        (shdr.sh_type == SHT_PROGBITS) && (shdr.sh_flags & SHF_EXECINSTR) &&
        (data->d_size > 0)) {
      if (section_name == ".text") {
        VLOG(4) << ".text section index: " << i;
        sectionsIndexes_[kTextSection] = i;
      }
      VLOG(2) << "Pushing prog data for section " << section_name;
      if (addProgData(section_name, data, i)) {
        return 1;
      }
    }
  }

  if (sectionsIndexes_[kSymbolSection] == kNotExists ||
      sectionsIndexes_[kStringSection] == kNotExists) {
    LOG(ERROR) << "Can't find expected sections in elf file\n"
               << "Maps section's pos: " << sectionsIndexes_[kMapsSection]
               << "\nSymbol table section's pos:"
               << sectionsIndexes_[kSymbolSection]
               << "\nString table section's pos:"
               << sectionsIndexes_[kStringSection];
    return 1;
  }
  return 0;
}

int BpfLoader::relocateMaps() {
  for (auto& prog_iter : progsData_) {
    if (prog_iter.second.progRelocs.size() == 0) {
      VLOG(2) << "Prog: " << prog_iter.second.name << " has no relocations";
      continue;
    }
    for (auto& reloc : prog_iter.second.progRelocs) {
      if (reloc.type == RelocType::RELO_LD64) {
        if (reloc.insn_idx > prog_iter.second.insns_cnt) {
          LOG(ERROR) << "Relocation index is out of bound";
          return 1;
        }
        VLOG(4) << "Rellocating map w/ fd: " << reloc.map_fd << " for program "
                << prog_iter.second.name;
        prog_iter.second.insns[reloc.insn_idx].src_reg = BPF_PSEUDO_MAP_FD;
        prog_iter.second.insns[reloc.insn_idx].imm = reloc.map_fd;
      }
    }
  }
  return 0;
}

int BpfLoader::relocateInsns() {
  for (auto& prog_iter : progsData_) {
    if (prog_iter.second.progRelocs.size() == 0) {
      VLOG(2) << "Prog: " << prog_iter.second.name << " has no relocations";
      continue;
    }
    for (auto& reloc : prog_iter.second.progRelocs) {
      if (reloc.type == RelocType::RELO_CALL) {
        if (sectionsIndexes_[kTextSection] == kNotExists) {
          LOG(ERROR) << ".text section not found. "
                     << "bpf_call rellocation not possible";
          return 1;
        }
        if (prog_iter.second.idx == sectionsIndexes_[kTextSection]) {
          LOG(ERROR) << "bpf_call relocation in .text section "
                     << "is not supported.";
          return 1;
        }
        if (!prog_iter.second.main_prog_cnt) {
          VLOG(4) << "Allocating memory for prog w/ bpf_call: "
                  << prog_iter.second.name;
          auto text_section_iter =
              progsData_.find(sectionsIndexes_[kTextSection]);
          if (text_section_iter == progsData_.end()) {
            LOG(ERROR) << "Internal Error: text section exists, but we can't "
                       << "find program description for it";
          }
          auto new_cnt =
              prog_iter.second.insns_cnt + text_section_iter->second.insns_cnt;
          VLOG(4) << "new instructions counter: " << new_cnt;
          auto new_insns = reinterpret_cast<struct bpf_insn*>(std::realloc(
              prog_iter.second.insns, new_cnt * sizeof(struct bpf_insn)));
          if (!new_insns) {
            LOG(ERROR) << "Allocation for new prog's instructions failed.";
            return 1;
          }
          std::memcpy(
              new_insns + prog_iter.second.insns_cnt,
              text_section_iter->second.insns,
              text_section_iter->second.insns_cnt * sizeof(struct bpf_insn));
          prog_iter.second.insns = new_insns;
          prog_iter.second.main_prog_cnt = prog_iter.second.insns_cnt;
          prog_iter.second.insns_cnt = new_cnt;
          prog_iter.second.size = new_cnt * sizeof(struct bpf_insn);
        }
        VLOG(4) << "Processing bpf_call reloc for prog: "
                << prog_iter.second.name << " at index " << reloc.insn_idx
                << " and main_prog_cnt is " << prog_iter.second.main_prog_cnt
                << " instruction's imm "
                << prog_iter.second.insns[reloc.insn_idx].imm;

        prog_iter.second.insns[reloc.insn_idx].imm +=
            (prog_iter.second.main_prog_cnt - reloc.insn_idx);
        VLOG(4) << "New imm: " << prog_iter.second.insns[reloc.insn_idx].imm;
      }
    }
  }
  return 0;
}

int BpfLoader::loadBpfProgs() {
  for (auto& prog_iter : progsData_) {
    if (prog_iter.second.name == ".text") {
      continue;
    }
    VLOG(2) << "Loading bpf prog: " << prog_iter.second.name
            << "\ninsns: " << prog_iter.second.insns_cnt
            << "\nsize: " << prog_iter.second.size
            << "\ninsns: " << prog_iter.second.insns
            << "\nlicense: " << license_
            << "\nkernel version: " << kernelVersion_;
    std::string bpf_log_buf(kLogBufSize, '\0');
    auto prog_fd = ebpf_prog_load(
        prog_iter.second.type,
        prog_iter.second.insns,
        prog_iter.second.size,
        license_.c_str(),
        kernelVersion_,
        const_cast<char*>(bpf_log_buf.data()),
        kLogBufSize);

    if (prog_fd < 0) {
      LOG(ERROR) << "Error while loading " << prog_iter.second.name;
      std::cout << "log: " << bpf_log_buf << std::endl;
      LOG(ERROR) << "Error: " << std::strerror(errno) << " errno: " << errno;
      return 1;
    }

    progs_[prog_iter.second.name] = prog_fd;
    progsCntr_++;
    std::free(prog_iter.second.insns);
  }
  return 0;
}

int BpfLoader::loadBpfFile(const std::string& path, const bpf_prog_type type) {
  initializeTempVars();
  int fd = -1;
  SCOPE_EXIT {
    elf_end(elf_);
    if (fd > 0) {
      ::close(fd);
    }
  };
  progType_ = type;

  if (elf_version(EV_CURRENT) == EV_NONE) {
    LOG(ERROR) << "Elf library is too old. Exiting.";
    return 1;
  }

  fd = ::open(path.c_str(), O_RDONLY, 0);
  if (fd < 0) {
    LOG(ERROR) << "Can't open file w/ BPF program: " << path
               << "Error: " << std::strerror(errno);
    return 1;
  }

  elf_ = elf_begin(fd, ELF_C_READ, nullptr);
  if (!elf_) {
    LOG(ERROR) << "Can't allocate new elf descriptor for file: " << path;
    return 1;
  }

  if (gelf_getehdr(elf_, &ehdr_) != &ehdr_) {
    LOG(ERROR) << "Can't read elf header for file: " << path;
    return 1;
  }

  if (collectElfData(path)) {
    return 1;
  }

  VLOG(2) << "Loading symbols";
  loadSymbols(elf_);

  if (sectionsIndexes_[kMapsSection] == kNotExists) {
    VLOG(2) << "BPF program w/o maps";
  } else {
    VLOG(2) << "Loading maps";
    loadMaps(elf_);
  }

  VLOG(2) << "Collecting relocations";
  if (collectReloc()) {
    return 1;
  }

  VLOG(2) << "Applying relocations for maps (if they exist)";
  if (relocateMaps()) {
    return 1;
  }

  VLOG(2) << "Applying relocations for instructions";
  if (relocateInsns()) {
    return 1;
  }

  VLOG(2) << "Loading bpf programs";
  if (loadBpfProgs()) {
    return 1;
  }

  return 0;
}

} // namespace katran
