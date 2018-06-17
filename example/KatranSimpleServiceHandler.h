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

#include <mutex>
#include <vector>

#include "katran/if/gen-cpp2/KatranService.h"
#include "katran/lib/KatranLb.h"

namespace lb {
namespace katran {

/**
 * Simple example of libkatran usage. local thrift RPC endpoint will be
 * responsible for handling incoming requests and change the state of load
 * balancer's forwarding table.
 */
class KatranSimpleServiceHandler : virtual public KatranServiceSvIf {
 public:
  KatranSimpleServiceHandler() = delete;
  explicit KatranSimpleServiceHandler(const ::katran::KatranConfig& config);

  bool changeMac(std::unique_ptr<::lb::katran::Mac> newMac) override;

  void getMac(::lb::katran::Mac& _return) override;

  bool addVip(std::unique_ptr<::lb::katran::VipMeta> vipMeta) override;

  bool delVip(std::unique_ptr<::lb::katran::Vip> vip) override;

  void getAllVips(std::vector<::lb::katran::Vip>& _return) override;

  bool modifyVip(std::unique_ptr<::lb::katran::VipMeta> vipMeta) override;

  int64_t getVipFlags(std::unique_ptr<::lb::katran::Vip> vip) override;

  bool addRealForVip(
      std::unique_ptr<::lb::katran::Real> real,
      std::unique_ptr<::lb::katran::Vip> vip) override;

  bool delRealForVip(
      std::unique_ptr<::lb::katran::Real> real,
      std::unique_ptr<::lb::katran::Vip> vip) override;

  bool modifyRealsForVip(
      ::lb::katran::Action action,
      std::unique_ptr<::lb::katran::Reals> reals,
      std::unique_ptr<::lb::katran::Vip> vip) override;

  void getRealsForVip(
      ::lb::katran::Reals& _return,
      std::unique_ptr<::lb::katran::Vip> vip) override;

  bool modifyQuicRealsMapping(
      ::lb::katran::Action action,
      std::unique_ptr<::lb::katran::QuicReals> reals) override;

  void getQuicRealsMapping(::lb::katran::QuicReals& _return) override;

  void getStatsForVip(
      ::lb::katran::Stats& _return,
      std::unique_ptr<::lb::katran::Vip> vip) override;

  void getLruStats(::lb::katran::Stats& _return) override;

  void getLruMissStats(::lb::katran::Stats& _return) override;

  void getLruFallbackStats(::lb::katran::Stats& _return) override;

  void getIcmpTooBigStats(::lb::katran::Stats& _return) override;

  bool addHealthcheckerDst(
      std::unique_ptr<::lb::katran::Healthcheck> healthcheck) override;

  bool delHealthcheckerDst(int32_t somark) override;

  void getHealthcheckersDst(::lb::katran::hcMap& _return) override;

 private:
  ::katran::KatranLb lb_;

  std::mutex giant_;

  bool hcForwarding_;
};

} // namespace katran
} // namespace lb
