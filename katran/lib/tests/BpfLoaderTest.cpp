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

#include <gtest/gtest.h>

#include "katran/lib/BpfLoader.h"

// Skeleton headers provide compiled BPF ELF as byte arrays. Opening the
// skeleton creates a bpf_object in userspace without requiring kernel support.
#include "katran/lib/bpf/balancer_kern_test.skel.h"
// xdpchainer variant uses SEC("freplace/...") -> BPF_PROG_TYPE_EXT
#include "katran/lib/bpf/balancer_kern_origin_gue_xdpchainer.skel.h"

using katran::BpfLoader;

TEST(XdpHasFragsTest, MaybeSetFlagSetsOnXdpProg) {
  auto* skel = balancer_kern_test__open();
  ASSERT_NE(skel, nullptr);

  ::bpf_program* prog;
  bool foundXdpProg = false;
  bpf_object__for_each_program(prog, skel->obj) {
    if (bpf_program__type(prog) == BPF_PROG_TYPE_XDP) {
      EXPECT_EQ(bpf_program__flags(prog) & BPF_F_XDP_HAS_FRAGS, 0u);

      BpfLoader::maybeSetXdpHasFragsFlag(prog, /*xdpHasFrags=*/true);

      EXPECT_NE(bpf_program__flags(prog) & BPF_F_XDP_HAS_FRAGS, 0u);
      foundXdpProg = true;
    }
  }
  EXPECT_TRUE(foundXdpProg)
      << "Expected at least one XDP program in the BPF object";

  balancer_kern_test__destroy(skel);
}

TEST(XdpHasFragsTest, MaybeSetFlagSkipsWhenDisabled) {
  auto* skel = balancer_kern_test__open();
  ASSERT_NE(skel, nullptr);

  ::bpf_program* prog;
  bpf_object__for_each_program(prog, skel->obj) {
    BpfLoader::maybeSetXdpHasFragsFlag(prog, /*xdpHasFrags=*/false);
    EXPECT_EQ(bpf_program__flags(prog) & BPF_F_XDP_HAS_FRAGS, 0u)
        << "Flag should not be set when xdpHasFrags is false";
  }

  balancer_kern_test__destroy(skel);
}

TEST(XdpHasFragsTest, MaybeSetFlagSetsOnExtProg) {
  auto* skel = balancer_kern_origin_gue_xdpchainer__open();
  ASSERT_NE(skel, nullptr);

  ::bpf_program* prog;
  bool foundExtProg = false;
  bpf_object__for_each_program(prog, skel->obj) {
    if (bpf_program__type(prog) == BPF_PROG_TYPE_EXT) {
      EXPECT_EQ(bpf_program__flags(prog) & BPF_F_XDP_HAS_FRAGS, 0u);

      BpfLoader::maybeSetXdpHasFragsFlag(prog, /*xdpHasFrags=*/true);

      EXPECT_NE(bpf_program__flags(prog) & BPF_F_XDP_HAS_FRAGS, 0u)
          << "Flag should be set on BPF_PROG_TYPE_EXT (xdpchainer) programs";
      foundExtProg = true;
    }
  }
  EXPECT_TRUE(foundExtProg)
      << "Expected at least one EXT program in the xdpchainer BPF object";

  balancer_kern_origin_gue_xdpchainer__destroy(skel);
}

TEST(XdpHasFragsTest, MaybeSetFlagPreservesExistingFlags) {
  auto* skel = balancer_kern_test__open();
  ASSERT_NE(skel, nullptr);

  ::bpf_program* prog;
  bpf_object__for_each_program(prog, skel->obj) {
    if (bpf_program__type(prog) == BPF_PROG_TYPE_XDP) {
      auto originalFlags = bpf_program__flags(prog);

      BpfLoader::maybeSetXdpHasFragsFlag(prog, /*xdpHasFrags=*/true);

      auto newFlags = bpf_program__flags(prog);
      EXPECT_EQ(newFlags & ~BPF_F_XDP_HAS_FRAGS, originalFlags)
          << "OR'ing in BPF_F_XDP_HAS_FRAGS should not clear existing flags";
      EXPECT_NE(newFlags & BPF_F_XDP_HAS_FRAGS, 0u);
    }
  }

  balancer_kern_test__destroy(skel);
}
