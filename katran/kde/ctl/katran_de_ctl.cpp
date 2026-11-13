#include <CLI/CLI.hpp>
#include <folly/init/Init.h>
#include "katran/kde/ctl/CliParser.h"
#include "katran/kde/ctl/Commands.h"
#include "katran/kde/ctl/Utils.h"

using namespace katran_de::ctl;

int main(int argc, char* argv[]) {
  auto options = folly::InitOptions().removeFlags(false).useGFlags(false);
  folly::Init init(&argc, &argv, options);

  auto cli = CliParser::genCliApp(
      install, clean, stats, DirectEncapMode::CLIENT, ping);
  CLI11_PARSE(*cli, argc, argv);
  return 0;
}
