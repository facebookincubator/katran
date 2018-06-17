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
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "katran.grpc.pb.h"
#include "katran/lib/KatranLb.h"
#include <grpc++/grpc++.h>

using grpc::Server;
using grpc::ServerContext;
using grpc::Status;

namespace lb {
namespace katran {

class KatranGrpcService final : public KatranService::Service {
public:
  KatranGrpcService() = delete;

  explicit KatranGrpcService(const ::katran::KatranConfig &config);

  Status changeMac(ServerContext *context, const Mac *request,
                   Bool *response) override;

  Status getMac(ServerContext *context, const Empty *request,
                Mac *response) override;

  Status addVip(ServerContext *context, const VipMeta *request,
                Bool *response) override;

  Status delVip(ServerContext *context, const Vip *request,
                Bool *response) override;

  Status getAllVips(ServerContext *context, const Empty *request,
                    Vips *response) override;

  Status modifyVip(ServerContext *context, const VipMeta *request,
                   Bool *response) override;

  Status getVipFlags(ServerContext *context, const Vip *request,
                     Flags *response) override;

  Status addRealForVip(ServerContext *context, const realForVip *request,
                       Bool *response) override;

  Status delRealForVip(ServerContext *context, const realForVip *request,
                       Bool *response) override;

  Status modifyRealsForVip(ServerContext *context,
                           const modifiedRealsForVip *request,
                           Bool *response) override;

  Status getRealsForVip(ServerContext *context, const Vip *request,
                        Reals *response) override;

  Status modifyQuicRealsMapping(ServerContext *context,
                                const modifiedQuicReals *request,
                                Bool *response) override;

  Status getQuicRealsMapping(ServerContext *context, const Empty *request,
                             QuicReals *response) override;

  Status getStatsForVip(ServerContext *context, const Vip *request,
                        Stats *response) override;

  Status getLruStats(ServerContext *context, const Empty *request,
                     Stats *response) override;

  Status getLruMissStats(ServerContext *context, const Empty *request,
                         Stats *response) override;

  Status getLruFallbackStats(ServerContext *context, const Empty *request,
                             Stats *response) override;

  Status getIcmpTooBigStats(ServerContext *context, const Empty *request,
                            Stats *response) override;

  Status addHealthcheckerDst(ServerContext *context, const Healthcheck *request,
                             Bool *response) override;

  Status delHealthcheckerDst(ServerContext *context, const Somark *request,
                             Bool *response) override;

  Status getHealthcheckersDst(ServerContext *context, const Empty *request,
                              hcMap *response) override;

private:
  ::katran::KatranLb lb_;

  std::mutex giant_;

  bool hcForwarding_;
};

} // namespace katran
} // namespace lb
