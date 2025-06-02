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

#pragma once
#include <string>
#include <vector>
#include "katran/lib/KatranLb.h"
#include "katran/lib/testing/KatranTestProvision.h"

namespace katran {
namespace testing {

bool testSimulator(katran::KatranLb& lb);
KatranTestParam createDefaultTestParam(TestMode testMode);
KatranTestParam createTPRTestParam();
KatranTestParam createUdpStableRtTestParam();
KatranTestParam createXPopDecapTestParam();
KatranTestParam createIcmpTooBigTestParam();
void testOptionalLbCounters(katran::KatranLb& lb, KatranTestParam& testParam);
void testStableRtCounters(katran::KatranLb& lb, KatranTestParam& testParam);
void validateMapSize(
    katran::KatranLb& lb,
    const std::string& map_name,
    int expected_current,
    int expected_max);
void preTestOptionalLbCounters(
    katran::KatranLb& lb,
    const std::string& healthcheckingProg);
void postTestOptionalLbCounters(
    katran::KatranLb& lb,
    const std::string& healthcheckingProg);
bool testLbCounters(katran::KatranLb& lb, KatranTestParam& testParam);
void testXPopDecapCounters(katran::KatranLb& lb, KatranTestParam& testParam);
bool testIcmpTooBigCounters(katran::KatranLb& lb, KatranTestParam& testParam);
std::string toString(katran::KatranFeatureEnum feature);

} // namespace testing
} // namespace katran
