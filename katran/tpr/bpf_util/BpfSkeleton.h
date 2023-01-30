// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <bpf/libbpf.h>
#include <stdlib.h>

#include <katran/tpr/bpf_util/SystemError.h>

namespace katran_tpr {

template <typename T>
class BpfSkeleton {
 private:
  T* skel_;

 private:
  BpfSkeleton() : skel_(nullptr) {}

 public:
  ~BpfSkeleton() {
    if (skel_) {
      T::destroy(skel_);
    }
  }

  // Make them deleted to keep it simple and safe
  BpfSkeleton(const BpfSkeleton&) = delete;
  BpfSkeleton& operator=(const BpfSkeleton&) = delete;

  BpfSkeleton(BpfSkeleton&&) = delete;
  BpfSkeleton& operator=(BpfSkeleton&&) = delete;

  static BpfSkeleton make() {
    return BpfSkeleton<T>();
  }

  static folly::ByteRange elfBytes() {
    size_t size{0};
    auto bytes = static_cast<const unsigned char*>(T::elf_bytes(&size));
    folly::ByteRange buffer(bytes, size);

    return buffer;
  }

  SystemMaybe<folly::Unit> open(
      const struct bpf_object_open_opts* opts = nullptr) noexcept {
    if (skel_) {
      return SYSTEM_ERROR(EBUSY, "BpfSkeleton has already been opened");
    }

    skel_ = T::open(opts);
    if (auto error = libbpf_get_error(skel_)) {
      skel_ = nullptr;
      return SYSTEM_ERROR(error, "BpfSkeleton open failed");
    }

    return noSystemError();
  }

  SystemMaybe<folly::Unit> load() noexcept {
    if (skel_) {
      if (auto error = T::load(skel_)) {
        return SYSTEM_ERROR(error, "BpfSkeleton load failed");
      }

      return noSystemError();
    } else {
      return SYSTEM_ERROR(EINVAL, "BpfSkeleton is invalid");
    }
  }

  SystemMaybe<folly::Unit> attach() noexcept {
    if (skel_) {
      if (auto error = T::attach(skel_)) {
        return SYSTEM_ERROR(error, "BpfSkeleton attach failed");
      }

      return noSystemError();
    } else {
      return SYSTEM_ERROR(EINVAL, "BpfSkeleton is invalid");
    }
  }

  void detach() noexcept {
    if (skel_) {
      return T::detach(skel_);
    }
  }

  const T* operator->() const noexcept {
    return skel_;
  }

  T* operator->() noexcept {
    return skel_;
  }
};

} // namespace katran_tpr
