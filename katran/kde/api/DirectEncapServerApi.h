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
#include <folly/logging/xlog.h>

#include "katran/kde/api/DirectEncapApiBase.h"
#include "katran/kde/core/ServerDirectEncap.h"

namespace katran_de {

struct ServerTag {};

struct DirectEncapServerStats {
  kde_stats so_stats{0};
};

class DirectEncapServerApi : public DirectEncapApiBase {
 public:
  static bool installWithParams(const KdeInstallParams& params);
  static void uninstall();
  static DirectEncapServerStats stats();

  static std::shared_ptr<DirectEncapServerApi> getInstance();

  ~DirectEncapServerApi() override {
    uninstallImpl();
  }

  // Because is supposed to be used as a singleton, we delete these
  DirectEncapServerApi(const DirectEncapServerApi&) = delete;
  DirectEncapServerApi& operator=(const DirectEncapServerApi&) = delete;
  DirectEncapServerApi(DirectEncapServerApi&&) = delete;
  DirectEncapServerApi& operator=(DirectEncapServerApi&&) = delete;

 protected:
  bool initImpl(const KdeInstallParams& params) override;
  void uninstallImpl() override;
  DirectEncapServerStats getStatsImpl();
  void checkKillswitch() override;

  katran_tpr::ServerDirectEncap* getImpl() override {
    return deServer_.get();
  }

 private:
  DirectEncapServerApi() = default; // Private constructor only for singleton
  std::unique_ptr<katran_tpr::ServerDirectEncap> deServer_{nullptr};

  friend class folly::Singleton<DirectEncapServerApi, ServerTag>;
};

} // namespace katran_de
