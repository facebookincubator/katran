/* (c) Meta Platforms, Inc. and affiliates
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
#include <fmt/core.h>
#include <folly/CppAttributes.h>
#include <folly/FileUtil.h>
#include <folly/Function.h>
#include <folly/ScopeGuard.h>
#include <folly/String.h>
#include <glog/logging.h>
#include <libmnl/libmnl.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "katran/lib/BaseBpfAdapter.h"

namespace katran {

class BpfBatchUtil {
 public:
  template <typename KeyT, typename HashT = std::hash<KeyT>>
  static int bpfMapDeleteBatch(
      int map_fd,
      const std::unordered_set<KeyT, HashT>& keys) {
    struct bpf_map_info mapInfo {};
    auto err = BaseBpfAdapter::getBpfMapInfo(map_fd, &mapInfo);
    if (err) {
      LOG(ERROR) << "Error while retrieving map metadata for fd " << map_fd
                 << " : " << folly::errnoStr(errno);
      return err;
    }

    if (sizeof(KeyT) != mapInfo.key_size) {
      LOG(ERROR) << "caller used the wrong KeyT for the given map";
      return -EINVAL;
    }

    uint32_t count = keys.size();
    std::vector<KeyT> key_buf(keys.begin(), keys.end());
    int deleteErr = 0;

    DECLARE_LIBBPF_OPTS(
        bpf_map_batch_opts, opts, .elem_flags = 0, .flags = 0, );

    deleteErr = bpf_map_delete_batch(map_fd, key_buf.data(), &count, &opts);

    if (deleteErr) {
      LOG(ERROR) << "Failed to perform batch delete, errno = "
                 << folly::errnoStr(errno);
      return deleteErr;
    }

    if (count < keys.size()) {
      LOG(WARNING) << "Batch delete only deleted " << count
                   << " elements out of " << keys.size();
    }

    return 0;
  }

  template <typename KeyT, typename ValueT, typename HashT = std::hash<KeyT>>
  static int bpfMapReadBatch(
      int map_fd,
      std::unordered_map<KeyT, std::vector<ValueT>>& foundMap,
      std::uint32_t num_cpus = 1,
      std::uint32_t batch_sz = 128) {
    struct bpf_map_info mapInfo {};
    auto err = BaseBpfAdapter::getBpfMapInfo(map_fd, &mapInfo);
    if (err) {
      LOG(ERROR) << "Error while retrieving map metadata for fd " << map_fd
                 << " : " << folly::errnoStr(errno);
      return err;
    }

    if (sizeof(KeyT) != mapInfo.key_size ||
        sizeof(ValueT) != mapInfo.value_size) {
      LOG(ERROR) << "caller used the wrong KeyT/ValueT for the given map";
      return -EINVAL;
    }

    auto blob_size = num_cpus * sizeof(ValueT);
    auto blob_buf_size = batch_sz * blob_size;
    std::vector<KeyT> key_buf(batch_sz);
    std::vector<char> val_blob_buf(blob_buf_size);
    int lookupErr = 0;

    void* inKey = nullptr; // NULL to start a new dump
    void* nextKey = nullptr;

    DECLARE_LIBBPF_OPTS(
        bpf_map_batch_opts, opts, .elem_flags = 0, .flags = 0, );

    while (!lookupErr) {
      __u32 count = batch_sz; // in/out parameter for each call

      lookupErr = bpf_map_lookup_batch(
          map_fd,
          &inKey,
          &nextKey,
          key_buf.data(),
          val_blob_buf.data(),
          &count,
          &opts);

      if (lookupErr && lookupErr != -ENOENT) {
        // ENOENT is expected when we reach the end of the map
        LOG(ERROR) << "Failed to perform batch lookup, errno = "
                   << folly::errnoStr(-lookupErr);
        return lookupErr;
      }

      for (uint32_t i = 0; i < count; ++i) {
        const KeyT& k = key_buf[i];
        if (foundMap.contains(k)) {
          LOG(ERROR) << "Found duplicate key in returned bpf batch map";
          continue;
        }
        auto* raw = reinterpret_cast<ValueT*>(&val_blob_buf[i * blob_size]);
        std::vector<ValueT> values(raw, raw + num_cpus);
        foundMap.emplace(k, std::move(values));
      }
      inKey = nextKey; // nextKey is the new inKey
    }
    return 0;
  }

  template <typename KeyT, typename ValueT, typename HashT = std::hash<KeyT>>
  static int bpfMapLookupBatch(
      int map_fd,
      const std::unordered_set<KeyT, HashT>& keys,
      std::unordered_map<KeyT, std::vector<ValueT>>& foundMap,
      std::uint32_t num_cpus = 1,
      std::uint32_t batch_sz = 128) {
    struct bpf_map_info mapInfo {};
    auto err = BaseBpfAdapter::getBpfMapInfo(map_fd, &mapInfo);
    if (err) {
      LOG(ERROR) << "Error while retrieving map metadata for fd " << map_fd
                 << " : " << folly::errnoStr(errno);
      return err;
    }

    if (sizeof(KeyT) != mapInfo.key_size ||
        sizeof(ValueT) != mapInfo.value_size) {
      LOG(ERROR) << "caller used the wrong KeyT/ValueT for the given map";
      return -EINVAL;
    }

    auto blob_size = num_cpus * sizeof(ValueT);
    auto blob_buf_size = batch_sz * blob_size;
    std::vector<KeyT> key_buf(batch_sz);
    std::vector<char> val_blob_buf(blob_buf_size);
    int lookupErr = 0;

    void* inKey = nullptr; // NULL to start a new dump
    void* nextKey = nullptr;
    std::size_t remaining = keys.size();

    DECLARE_LIBBPF_OPTS(
        bpf_map_batch_opts, opts, .elem_flags = 0, .flags = 0, );

    while (!lookupErr && remaining > 0) {
      __u32 count = batch_sz; // in/out parameter for each call

      lookupErr = bpf_map_lookup_batch(
          map_fd,
          &inKey,
          &nextKey,
          key_buf.data(),
          val_blob_buf.data(),
          &count,
          &opts);

      if (lookupErr && lookupErr != -ENOENT) {
        // ENOENT is expected when we reach the end of the map
        LOG(ERROR) << "Failed to perform batch lookup, errno = "
                   << folly::errnoStr(-lookupErr);
        return lookupErr;
      }

      for (uint32_t i = 0; i < count; ++i) {
        const KeyT& k = key_buf[i];
        auto it = keys.find(key_buf[i]);
        if (keys.find(k) == keys.end()) {
          continue;
        }
        if (foundMap.contains(k)) {
          LOG(ERROR) << "Found duplicate key in returned bpf batch map";
          continue;
        }
        auto* raw = reinterpret_cast<ValueT*>(&val_blob_buf[i * blob_size]);
        std::vector<ValueT> values(raw, raw + num_cpus);
        foundMap.emplace(*it, std::move(values));
      }
      remaining = keys.size() - foundMap.size();
      inKey = nextKey; // nextKey is the new inKey
    }
    if (remaining > 0) {
      LOG(WARNING) << "Failed to find " << remaining << " keys in bpf map "
                   << mapInfo.name;
    }

    return 0;
  }

 private:
};

} // namespace katran
