/* Copyright (C) 2019-present, Facebook, Inc.
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

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <katran/decap/tc_bpf/tc_srcmatch.skel.h>
#include "katran/decap/testing/TcSrcMatchTestFixtures.h"
#include "katran/lib/testing/framework/BpfTester.h"

int main(int argc, char** argv) {
  gflags::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  FLAGS_logtostderr = 1;

  auto* skel = tc_srcmatch__open();
  if (!skel) {
    LOG(FATAL) << "Failed to open tc_srcmatch skeleton";
  }

  if (tc_srcmatch__load(skel)) {
    LOG(FATAL) << "Failed to load tc_srcmatch skeleton";
  }

  auto progFd = bpf_program__fd(skel->progs.tc_srcmatch);
  if (progFd < 0) {
    LOG(FATAL) << "Failed to get prog fd for tc_srcmatch";
  }

  auto fixtures = katran::testing::buildTcSrcMatchFixtures();

  katran::TesterConfig config;
  config.testData = fixtures;
  katran::BpfTester tester(config);

  std::vector<struct __sk_buff> ctxs(fixtures.size());
  auto success = tester.testClsFromFixture(progFd, ctxs);

  tc_srcmatch__destroy(skel);
  return success ? 0 : 1;
}
