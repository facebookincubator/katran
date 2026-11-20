// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <system_error>

#include <folly/Conv.h>
#include <folly/Expected.h>

namespace katran_tpr {

// Modules that primarily interact with the OS should report errors by
// returning `SystemMaybe`, and **NOT** via:
//  - `bool` return values -- hard to read
//  - `folly::exception_wrapper` return values -- hard to inspect error codes
//  - `throw`ing exceptions -- we are not in an exception-savvy codebase
template <typename Value>
using SystemMaybe = folly::Expected<Value, std::system_error>;

#define SYSTEM_ERROR(c, ...) \
  systemError(c, "[", __FILE__, ":", __LINE__, "] ", ##__VA_ARGS__)

template <typename... Msg>
[[nodiscard]] auto systemError(int err, Msg&&... msg) {
  return folly::makeUnexpected(
      std::system_error(
          err,
          std::system_category(),
          folly::to<std::string>(std::forward<Msg>(msg)...)));
}

template <typename... Msg>
[[nodiscard]] auto systemError(std::error_code errCode, Msg&&... msg) {
  return folly::makeUnexpected(
      std::system_error(
          errCode, folly::to<std::string>(std::forward<Msg>(msg)...)));
}

// Use this to add more human-readable context to an existing system_error,
// such as when you have an outer function propagating an inner function's
// error message. Usage:
//
//   auto maybePipe = makePipe();
//   if (maybePipe.hasError()) {
//     return SYSTEM_ERROR(maybePipe.error(), "Making stdout for", task);
//   }
//
// Will output:
//
//   Making stdout for TASK -- [pipe error]: Invalid argument: Invalid argument
//
// Unfortunately, this duplicates the system error message, but this is a
// design bug in `system_error`.
template <typename... Msg>
[[nodiscard]] auto systemError(std::system_error err, Msg&&... msg) {
  return folly::makeUnexpected(
      std::system_error(
          err.code(),
          folly::to<std::string>(
              folly::to<std::string>(std::forward<Msg>(msg)...),
              " -- ",
              err.what())));
}

// "Success" return value for a function returning no data.
[[nodiscard]] inline SystemMaybe<folly::Unit> noSystemError() {
  return folly::unit;
}

#define __SAFE_CONCAT(a, b) __CONCAT(a, b)
#define __UNIQ_ID(str) __SAFE_CONCAT(uniq__, __SAFE_CONCAT(str, __COUNTER__))
#define __EXPECT_SYSOK_IMPL(name, value)                 \
  ([&]() {                                               \
    auto name = (value);                                 \
    EXPECT_TRUE(name.hasValue()) << name.error().what(); \
    return name;                                         \
  }())
// Example usage:
//   auto value = EXPECT_SYS_OK(some_call_returning_sysmaybe(...));
// What it does? Check the status of returned value and forward it
// up. If error status is inside, it will nicely
// print it out and fail the test.
// Shouldn't we ASSERT_TRUE instead? Mostly no, folly::Expected
// will throw if you try to access value while error is stored
// in it. This exception will nicely terminate the test anyway. We
// may consider a version of this macro that extracts the value,
// but i prefer to not throw from macros
#define EXPECT_SYS_OK(expr) __EXPECT_SYSOK_IMPL(__UNIQ_ID(sysret), expr)
} // namespace katran_tpr
