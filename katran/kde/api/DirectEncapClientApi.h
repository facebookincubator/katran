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

#include <folly/Singleton.h>
#include "katran/kde/api/DirectEncapApiBase.h"
#include "katran/kde/core/ClientDirectEncap.h"

namespace katran_de {

struct ClientTag {};

struct DirectEncapClientStats {
  kde_stats so_stats{0};
  kde_tc_stats tc_stats{0};
};

class DirectEncapClientApi : public DirectEncapApiBase {
 public:
  static bool install();
  static bool installWithParams(const KdeInstallParams& params);
  static void uninstall();
  static DirectEncapClientStats stats();
  static KdeInstallParams paramsFromFlags();

  static std::shared_ptr<DirectEncapClientApi> getInstance();

  ~DirectEncapClientApi() override {
    uninstallImpl();
  }

  // Because is supposed to be used as a singleton, we delete these
  DirectEncapClientApi(const DirectEncapClientApi&) = delete;
  DirectEncapClientApi& operator=(const DirectEncapClientApi&) = delete;
  DirectEncapClientApi(DirectEncapClientApi&&) = delete;
  DirectEncapClientApi& operator=(DirectEncapClientApi&&) = delete;

 protected:
  bool initImpl(const KdeInstallParams& params) override;
  void uninstallImpl() override;
  DirectEncapClientStats getStatsImpl();
  void checkKillswitch() override;

  katran_tpr::ClientDirectEncap* getImpl() override {
    return deClient_.get();
  }

 private:
  DirectEncapClientApi() = default; // Private constructor only for singleton
  std::unique_ptr<katran_tpr::ClientDirectEncap> deClient_{nullptr};

  friend class folly::Singleton<DirectEncapClientApi, ClientTag>;
};

} // namespace katran_de
