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

#include "BaseBpfAdapter.h"
#include "BpfLoader.h"

extern "C" {
#include <bpf/bpf.h>
#include <linux/perf_event.h>
}

namespace katran {

class BpfAdapter : public BaseBpfAdapter {
 public:
  explicit BpfAdapter(bool set_limits = true);

  // BpfAdapter is not thread safe.  Discourage unsafe use by disabling copy
  // construction/assignment.
  BpfAdapter(BpfAdapter const&) = delete;
  BpfAdapter& operator=(BpfAdapter const&) = delete;

  int loadBpfProg(
      const std::string& bpf_prog,
      const bpf_prog_type type = BPF_PROG_TYPE_UNSPEC,
      bool use_names = false) override;

  int reloadBpfProg(
      const std::string& bpf_prog,
      const bpf_prog_type type = BPF_PROG_TYPE_UNSPEC) override;

  int loadBpfProg(
      const char* buf,
      int buf_size,
      const bpf_prog_type type = BPF_PROG_TYPE_UNSPEC,
      bool use_names = false,
      const char* objName = "buffer") override;

  int getMapFdByName(const std::string& name) override;

  bool isMapInProg(const std::string& progName, const std::string& name)
      override;

  int setInnerMapPrototype(const std::string& name, int map_fd) override;

  int getProgFdByName(const std::string& name) override;

  int updateSharedMap(const std::string& name, int fd) override;

 private:
  BpfLoader loader_;
};

} // namespace katran
