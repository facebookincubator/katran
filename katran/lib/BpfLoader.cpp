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
 */

#include "BpfLoader.h"
#include <glog/logging.h>
#include <array>

namespace katran {

namespace {
constexpr int kError = 1;
constexpr int kNotExists = -1;
constexpr int kSuccess = 0;
constexpr int kMaxSharedMapNameSize = 15;
} // namespace

namespace {

void checkBpfProgType(::bpf_object* obj, ::bpf_prog_type type) {
  if (type == BPF_PROG_TYPE_UNSPEC) {
    return;
  }
  ::bpf_program* prog;
  bpf_object__for_each_program(prog, obj) {
    CHECK_EQ(bpf_program__type(prog), type);
  }
}

std::string libBpfErrMsg(int err) {
  std::array<char, 128> buf{};
  libbpf_strerror(err, buf.data(), buf.size());
  return std::string(buf.begin(), buf.end());
}

} // namespace

BpfLoader::BpfLoader() {
  VLOG(1) << "Enabled libbpf strict mode";
  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
}

BpfLoader::~BpfLoader() {
  for (auto& obj : bpfObjects_) {
    closeBpfObject(obj.second);
  }
}

int BpfLoader::closeBpfObject(::bpf_object* obj) {
  ::bpf_object__close(obj);
  return kError;
}

int BpfLoader::getMapFdByName(const std::string& name) {
  auto map = maps_.find(name);
  if (map == maps_.end()) {
    LOG(ERROR) << "Can't find map w/ name: " << name;
    return kNotExists;
  } else {
    return map->second;
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

bool BpfLoader::isMapInProg(
    const std::string& progName,
    const std::string& name) {
  auto progMaps = currentMaps_.find(progName);
  if (progMaps == currentMaps_.end()) {
    return false;
  }
  return progMaps->second.find(name) != progMaps->second.end();
}

int BpfLoader::updateSharedMap(const std::string& name, int fd) {
  if (sharedMaps_.find(name) != sharedMaps_.end()) {
    LOG(ERROR) << "Shared maps name collision. Name: " << name;
    return kNotExists;
  } else if (name.size() > kMaxSharedMapNameSize) {
    LOG(ERROR) << "Shared map's name: " << name << " bigger than maximum "
               << " supported size: " << kMaxSharedMapNameSize;
    return kNotExists;
  } else {
    sharedMaps_[name] = fd;
    return kSuccess;
  }
}

int BpfLoader::setInnerMapPrototype(const std::string& name, int fd) {
  if (innerMapsProto_.find(name) != innerMapsProto_.end()) {
    LOG(ERROR) << "map-in-map prototype's name collision";
    return kError;
  }
  innerMapsProto_[name] = fd;
  return kSuccess;
}

int BpfLoader::loadBpfFile(
    const std::string& path,
    const bpf_prog_type type,
    bool use_names) {
  auto obj = ::bpf_object__open(path.c_str());
  const auto err = ::libbpf_get_error(obj);
  if (err) {
    LOG(ERROR) << "Error while opening bpf object: " << path
               << ", error: " << libBpfErrMsg(err);
    return kError;
  }
  return loadBpfObject(obj, path, type);
}

int BpfLoader::reloadBpfFromFile(
    const std::string& path,
    const bpf_prog_type type) {
  auto obj = ::bpf_object__open(path.c_str());
  const auto err = ::libbpf_get_error(obj);
  if (err) {
    LOG(ERROR) << "Error while opening bpf object: " << path
               << ", error: " << libBpfErrMsg(err);
    return kError;
  }
  return reloadBpfObject(obj, path, type);
}

int BpfLoader::loadBpfFromBuffer(
    const char* buf,
    int buf_size,
    const bpf_prog_type type,
    bool use_names,
    const char* objName) {
  LIBBPF_OPTS(bpf_object_open_opts, opts, .object_name = objName);
  auto obj = ::bpf_object__open_mem(buf, buf_size, &opts);
  const auto err = ::libbpf_get_error(obj);
  if (err) {
    LOG(ERROR) << "Error while opening bpf object from buffer, error: "
               << libBpfErrMsg(err);
    return kError;
  }
  return loadBpfObject(obj, objName, type);
}

int BpfLoader::reloadBpfObject(
    ::bpf_object* obj,
    const std::string& objName,
    const bpf_prog_type type) {
  ::bpf_program* prog;
  ::bpf_map* map;
  std::set<std::string> loadedProgNames;
  std::set<std::string> loadedMapNames;

  bpf_object__for_each_program(prog, obj) {
    // reload bpf program only if we have loaded it already. we distinct bpf
    // programs by their name
    if (progs_.find(::bpf_program__name(prog)) == progs_.end()) {
      LOG(ERROR) << "trying to reload not yet loaded program: "
                 << ::bpf_program__name(prog);
      return closeBpfObject(obj);
    }
  }

  bpf_map__for_each(map, obj) {
    auto map_name = ::bpf_map__name(map);
    auto shared_map_iter = sharedMaps_.find(map_name);
    if (shared_map_iter != sharedMaps_.end()) {
      VLOG(2) << "shared map found w/ a name: " << shared_map_iter->first
              << " fd: " << shared_map_iter->second;
      if (::bpf_map__reuse_fd(map, shared_map_iter->second)) {
        LOG(ERROR) << "error while trying to set fd of shared map: "
                   << shared_map_iter->first;
        return closeBpfObject(obj);
      }
      continue;
    }

    auto map_iter = maps_.find(map_name);
    if (map_iter != maps_.end()) {
      // we would reuse already loaded map. if they were not explicitly added as
      // shared maps we would make them such implicitly
      VLOG(2) << "map w/ a name: " << map_iter->first
              << " found. fd: " << map_iter->second << " Making it shared";
      if (updateSharedMap(map_name, map_iter->second)) {
        LOG(ERROR) << "Error while trying to update shared maps";
        return closeBpfObject(obj);
      }
      if (::bpf_map__reuse_fd(map, map_iter->second)) {
        LOG(ERROR)
            << "error while trying to reuse fd of a map while reloading bpf program: "
            << map_iter->first;
        return closeBpfObject(obj);
      }
      continue;
    }

    auto inner_map_iter = innerMapsProto_.find(map_name);
    if (inner_map_iter != innerMapsProto_.end()) {
      VLOG(2) << "setting inner id for map-in-map: " << inner_map_iter->first
              << " fd: " << inner_map_iter->second;
      if (bpf_map__set_inner_map_fd(map, inner_map_iter->second)) {
        LOG(ERROR) << "error while trying to set inner map fd for: "
                   << inner_map_iter->first
                   << " fd: " << inner_map_iter->second;
        return closeBpfObject(obj);
      }
    }
  }

  if (::bpf_object__load(obj)) {
    LOG(ERROR) << "error while trying to load bpf object: " << objName;
    return closeBpfObject(obj);
  }
  checkBpfProgType(obj, type);

  bpf_object__for_each_program(prog, obj) {
    // close old bpf program and (as we successfully reloaded it) and override
    // fd with a new one
    auto prog_name = ::bpf_program__name(prog);
    VLOG(4) << "closing old bpf program w/ name: " << prog_name;
    auto old_fd = progs_[prog_name];
    ::close(old_fd);
    VLOG(4) << "adding bpf program: " << prog_name
            << " with fd: " << ::bpf_program__fd(prog);
    progs_[prog_name] = ::bpf_program__fd(prog);
    loadedProgNames.insert(prog_name);
  }

  bpf_map__for_each(map, obj) {
    auto map_name = bpf_map__name(map);
    auto map_iter = maps_.find(map_name);
    if (map_iter == maps_.end()) {
      VLOG(4) << "adding bpf map: " << map_name
              << " with fd: " << ::bpf_map__fd(map);
      maps_[map_name] = bpf_map__fd(map);
    }
    loadedMapNames.insert(map_name);
  }

  for (auto& progName : loadedProgNames) {
    currentMaps_[progName] = loadedMapNames;
  }

  bpfObjects_[objName] = obj;
  return kSuccess;
}

int BpfLoader::loadBpfObject(
    ::bpf_object* obj,
    const std::string& objName,
    const bpf_prog_type type) {
  if (bpfObjects_.find(objName) != bpfObjects_.end()) {
    LOG(ERROR) << "collision while trying to load bpf object w/ name "
               << objName;
    return closeBpfObject(obj);
  }

  ::bpf_program* prog;
  ::bpf_map* map;
  std::set<std::string> loadedProgNames;
  std::set<std::string> loadedMapNames;

  bpf_object__for_each_program(prog, obj) {
    bpf_program__set_log_level(prog, 4);
    if (progs_.find(::bpf_program__name(prog)) != progs_.end()) {
      LOG(ERROR) << "bpf's program name collision: "
                 << ::bpf_program__name(prog);
      return closeBpfObject(obj);
    }
  }

  bpf_map__for_each(map, obj) {
    auto map_name = ::bpf_map__name(map);
    auto shared_map_iter = sharedMaps_.find(map_name);
    if (shared_map_iter != sharedMaps_.end()) {
      VLOG(2) << "shared map found w/ a name: " << shared_map_iter->first;
      if (::bpf_map__reuse_fd(map, shared_map_iter->second)) {
        LOG(ERROR) << "error while trying to set fd of shared map: "
                   << shared_map_iter->first;
        return closeBpfObject(obj);
      }
      continue;
    }
    if (maps_.find(map_name) != maps_.end()) {
      if (knownDuplicateMaps_.find(std::string(map_name)) !=
          knownDuplicateMaps_.end()) {
        VLOG(2) << "bpf ignoring map collision of - " << map_name;
        continue;
      }
      LOG(ERROR) << "bpf's map name collision - " << map_name;
      return closeBpfObject(obj);
    }
    auto inner_map_iter = innerMapsProto_.find(map_name);
    if (inner_map_iter != innerMapsProto_.end()) {
      VLOG(2) << "setting inner id for map-in-map: " << inner_map_iter->first
              << " fd: " << inner_map_iter->second;
      if (bpf_map__set_inner_map_fd(map, inner_map_iter->second)) {
        LOG(ERROR) << "error while trying to set inner map fd for: "
                   << inner_map_iter->first
                   << " fd: " << inner_map_iter->second;
        return closeBpfObject(obj);
      }
    }
  }

  if (::bpf_object__load(obj)) {
    LOG(ERROR) << "error while trying to load bpf object: " << objName;
    return closeBpfObject(obj);
  }

  checkBpfProgType(obj, type);

  bpf_object__for_each_program(prog, obj) {
    auto prog_name = ::bpf_program__name(prog);
    VLOG(4) << "adding bpf program: " << prog_name
            << " with fd: " << ::bpf_program__fd(prog);
    progs_[prog_name] = ::bpf_program__fd(prog);
    loadedProgNames.insert(prog_name);
  }

  bpf_map__for_each(map, obj) {
    auto map_name = ::bpf_map__name(map);
    VLOG(4) << "adding bpf map: " << map_name
            << " with fd: " << ::bpf_map__fd(map);
    maps_[map_name] = bpf_map__fd(map);
    loadedMapNames.insert(map_name);
  }

  for (auto& progName : loadedProgNames) {
    currentMaps_[progName] = loadedMapNames;
  }

  bpfObjects_[objName] = obj;
  return kSuccess;
}

const char* BpfLoader::getProgNameFromBpfProg(const struct bpf_program* prog) {
  return ::bpf_program__name(prog);
}

} // namespace katran
