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

#include "katran/lib/testing/framework/KatranTesterCli.h"

#include <CLI/CLI.hpp>

#include <cstdlib>
#include <map>
#include <string_view>

namespace katran::testing::cli {

bool usesCanonicalSyntax(int argc, char** argv) {
  if (argc < 2) {
    return false;
  }
  /* only the first argument selects the interface: legacy flag *values* can
   * be "test" or "bench" (e.g. --pcap_input test) and must not be caught */
  const std::string_view subcommand{argv[1]};
  return subcommand == "test" || subcommand == "bench";
}

folly::Expected<TesterCommand, int> parseKatranTesterCLI(
    int argc,
    char** argv) {
  CLI::App app{"Run Katran packet tests and benchmarks"};
  app.set_help_all_flag("--help-all", "Print all options");
  app.require_subcommand(1, 1);

  TestCommand test;
  BenchmarkCommand benchmark;
  enum class Protocol { kAll, kTcp, kUdp };
  Protocol protocol{Protocol::kAll};

  /* subcommands */
  auto* testSubcommand = app.add_subcommand("test", "Run packet tests");
  auto* benchmarkSubcommand =
      app.add_subcommand("bench", "Benchmark fixture packets");

  /* test command */
  testSubcommand->add_flag(
      "--check-counters", test.checkCounters, "Validate Katran counters");
  testSubcommand->add_option(
      "--balancer-prog,--balancer_prog",
      test.balancerProgPath,
      "Path to the balancer BPF program");

  /* benchmark command */
  benchmarkSubcommand
      ->add_option(
          "--repeat", benchmark.repeat, "Number of benchmark repetitions")
      ->check(CLI::PositiveNumber);
  const std::map<std::string, Protocol> protocols{
      {"all", Protocol::kAll},
      {"tcp", Protocol::kTcp},
      {"udp", Protocol::kUdp},
  };
  benchmarkSubcommand
      ->add_option("--proto", protocol, "Protocol selection: all, tcp, or udp")
      ->transform(CLI::CheckedTransformer(protocols, CLI::ignore_case));
  benchmarkSubcommand->add_option(
      "--balancer-prog,--balancer_prog",
      benchmark.balancerProgPath,
      "Path to the balancer BPF program");

  try {
    app.parse(argc, argv);
  } catch (const CLI::ParseError& error) {
    /* help is delivered as a ParseError too: exit() prints it and yields 0 */
    return folly::makeUnexpected(app.exit(error));
  }

  if (*testSubcommand) {
    return test;
  } else if (*benchmarkSubcommand) {
    switch (protocol) {
      case Protocol::kAll:
        break;
      case Protocol::kTcp:
        benchmark.positions = {1, 2, 3, 4, 5, 6};
        break;
      case Protocol::kUdp:
        benchmark.positions = {0};
        break;
    }
    return benchmark;
  }
  /* require_subcommand(1, 1) makes this unreachable, but the contract is that
   * we always hand back either a command or an exit code */
  return folly::makeUnexpected(EXIT_FAILURE);
}

} // namespace katran::testing::cli
