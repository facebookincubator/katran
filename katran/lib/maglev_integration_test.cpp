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

#include <gflags/gflags.h>
#include <algorithm>
#include <iostream>
#include <vector>

#include "CHHelpers.h"

DEFINE_int64(weight, 100, "weights per real");
DEFINE_int64(freq, 1, "how often real would have diff weight");
DEFINE_int64(difweight, 1, "diff weight for test");
DEFINE_int64(nreals, 400, "number of reals");
int main(int argc, char** argv) {
  gflags::ParseCommandLineFlags(&argc, &argv, true);

  std::vector<katran::Endpoint> endpoints;
  std::vector<uint32_t> freq(FLAGS_nreals, 0);
  katran::Endpoint endpoint;
  double n1 = 0;
  double n2 = 0;

  for (int i = 0; i < FLAGS_nreals; i++) {
    endpoint.num = i;
    endpoint.hash = 10 * i;
    if (i % FLAGS_freq == 0) {
      endpoint.weight = FLAGS_weight;
    } else {
      endpoint.weight = FLAGS_difweight;
    }
    endpoints.push_back(endpoint);
  }

  auto ch1 = katran::CHHelpers::GenerateMaglevHash(endpoints);
  endpoints.pop_back();
  auto ch2 = katran::CHHelpers::GenerateMaglevHash(endpoints);

  for (int i = 0; i < ch1.size(); i++) {
    freq[ch1[i]]++;
  }

  std::vector<uint32_t> sorted_freq(freq);

  std::sort(sorted_freq.begin(), sorted_freq.end());

  std::cout << "min freq is " << sorted_freq[0] << " max freq is "
            << sorted_freq[sorted_freq.size() - 1] << std::endl;

  std::cout << "p95 w: " << sorted_freq[(sorted_freq.size() / 20) * 19]
            << "\np75 w: " << sorted_freq[(sorted_freq.size() / 20) * 15]
            << "\np50 w: " << sorted_freq[sorted_freq.size() / 2]
            << "\np25 w: " << sorted_freq[sorted_freq.size() / 4]
            << "\np5 w: " << sorted_freq[sorted_freq.size() / 20] << std::endl;

  for (int i = 0; i < ch1.size(); i++) {
    if (ch1[i] != ch2[i]) {
      if (ch1[i] == (FLAGS_nreals - 1)) {
        n1++;
        continue;
      }
      n2++;
    }
  }

  std::cout << "changes for affected real: " << n1 << "; and for not affected "
            << n2 << " this is: " << n2 / ch1.size() * 100 << "%\n";

  return 0;
}
