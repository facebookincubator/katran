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

#include "BpfAdapter.h"

namespace katran {

BpfAdapter::BpfAdapter(bool set_limits)
    : BaseBpfAdapter(set_limits), loader_() {}

int BpfAdapter::loadBpfProg(
    const std::string& bpf_prog,
    const bpf_prog_type type,
    bool use_names) {
  return loader_.loadBpfFile(bpf_prog, type, use_names);
}

int BpfAdapter::reloadBpfProg(
    const std::string& bpf_prog,
    const bpf_prog_type type) {
  return loader_.reloadBpfFromFile(bpf_prog, type);
}

int BpfAdapter::loadBpfProg(
    const char* buf,
    int buf_size,
    const bpf_prog_type type,
    bool use_names,
    const char* objName) {
  return loader_.loadBpfFromBuffer(buf, buf_size, type, use_names, objName);
}

int BpfAdapter::getMapFdByName(const std::string& name) {
  return loader_.getMapFdByName(name);
}

int BpfAdapter::setInnerMapPrototype(const std::string& name, int map_fd) {
  return loader_.setInnerMapPrototype(name, map_fd);
}

int BpfAdapter::getProgFdByName(const std::string& name) {
  return loader_.getProgFdByName(name);
}

bool BpfAdapter::isMapInProg(
    const std::string& progName,
    const std::string& name) {
  return loader_.isMapInProg(progName, name);
}

int BpfAdapter::updateSharedMap(const std::string& name, int fd) {
  return loader_.updateSharedMap(name, fd);
}

} // namespace katran
