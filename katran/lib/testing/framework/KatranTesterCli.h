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
 */

#pragma once

#include <cstdint>
#include <string>
#include <variant>
#include <vector>

#include <folly/Expected.h>

namespace katran::testing::cli {
/* commands */
struct TestCommand {
  bool checkCounters{false};
  std::string balancerProgPath{"./balancer.bpf.o"};
};
struct BenchmarkCommand {
  uint32_t repeat{1000000};
  std::vector<int> positions{};
  std::string balancerProgPath{"./balancer.bpf.o"};
};
// TODO(shah256): add feature parity with legacy flags
// define union
using TesterCommand = std::variant<BenchmarkCommand, TestCommand>;

// Returns true when argv selects the canonical subcommand interface. Legacy
// invocations are deliberately left to gflags and its existing dispatcher.
// This makes it easier to deprecate the legacy interface later
bool usesCanonicalSyntax(int argc, char** argv);

// Returns the selected command, or the code the process should exit with
// cli11 treats --help as parse failure which makes optional<TesterCommand>
// whackamole
folly::Expected<TesterCommand, int> parseKatranTesterCLI(int argc, char** argv);
} // namespace katran::testing::cli
