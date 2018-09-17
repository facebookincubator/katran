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

namespace katran {

enum class RelocType {
  RELO_LD64, // map related relocation
  RELO_CALL, // bpf call related relocaiton
};

/**
 * struct which describe bpf's map
 */
struct bpf_map_def {
  unsigned int type;
  unsigned int key_size;
  unsigned int value_size;
  unsigned int max_entries;
  unsigned int map_flags;
  unsigned int inner_map_idx;
  unsigned int numa_node;
};

/**
 * struct which contains elf section header and data of relocation section
 */
struct RelocData {
  GElf_Shdr shdr;
  Elf_Data *data;
};

/**
 * struct which contains relocation descriptions (e.g. type, index, offset)
 */
struct RelocDesc {
  RelocType type;
  int insn_idx;
  union {
    int map_fd;
    int text_off;
  };
};

/**
 * struct which contains bpf program's related data. such as type,
 * instructions, relocation data etc.
 */
struct BpfProgData {
  std::vector<RelocDesc> progRelocs;
  std::string name;
  struct bpf_insn* insns{nullptr};
  bpf_prog_type type;
  int idx;
  int insns_cnt;
  int main_prog_cnt;
  int size;
};


}
