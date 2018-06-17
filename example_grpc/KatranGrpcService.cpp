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

#include "KatranGrpcService.h"

#include <glog/logging.h>

#include "katran/lib/MacHelpers.h"

using grpc::Server;
using grpc::ServerContext;
using grpc::Status;

namespace lb {
namespace katran {

using Guard = std::lock_guard<std::mutex>;

// translation helpers

::katran::VipKey translateVipObject(const Vip &vip) {
  ::katran::VipKey vk;
  vk.address = vip.address();
  vk.port = vip.port();
  vk.proto = vip.protocol();
  return vk;
}

::katran::NewReal translateRealObject(const Real &real) {
  ::katran::NewReal nr;
  nr.address = real.address();
  nr.weight = real.weight();
  return nr;
}

::katran::QuicReal translateQuicRealObject(const QuicReal &real) {
  ::katran::QuicReal qr;
  qr.address = real.address();
  qr.id = real.id();
  return qr;
}

Status returnStatus(bool result) {
  if (result) {
    return Status::OK;
  } else {
    return Status::CANCELLED;
  }
}

KatranGrpcService::KatranGrpcService(const ::katran::KatranConfig &config)
    : lb_(config), hcForwarding_(config.enableHc) {

  LOG(INFO) << "Starting Katran";
  lb_.loadBpfProgs();
  lb_.attachBpfProgs();
}

Status KatranGrpcService::changeMac(ServerContext *context, const Mac *request,
                                    Bool *response) {

  Guard lock(giant_);
  auto mac = ::katran::convertMacToUint(request->mac());
  auto res = lb_.changeMac(mac);
  response->set_success(res);
  return returnStatus(res);
}

Status KatranGrpcService::getMac(ServerContext *context, const Empty *request,
                                 Mac *response) {

  Guard lock(giant_);
  auto mac = lb_.getMac();
  response->set_mac(::katran::convertMacToString(mac));
  return Status::OK;
}

Status KatranGrpcService::addVip(ServerContext *context, const VipMeta *request,
                                 Bool *response) {

  bool res;
  auto vk = translateVipObject(request->vip());

  try {
    Guard lock(giant_);
    res = lb_.addVip(vk, request->flags());
  } catch (const std::exception &e) {
    LOG(INFO) << "Exception while adding new vip: " << e.what();
    res = false;
  }
  response->set_success(res);
  return returnStatus(res);
}

Status KatranGrpcService::delVip(ServerContext *context, const Vip *request,
                                 Bool *response) {

  auto vk = translateVipObject(*request);
  Guard lock(giant_);
  auto res = lb_.delVip(vk);
  response->set_success(res);
  return returnStatus(res);
}

Status KatranGrpcService::getAllVips(ServerContext *context,
                                     const Empty *request, Vips *response) {

  Vip vip;
  Guard lock(giant_);
  auto vips = lb_.getAllVips();
  for (auto &v : vips) {
    vip.set_address(v.address);
    vip.set_port(v.port);
    vip.set_protocol(v.proto);
    auto rvip = response->add_vips();
    *rvip = vip;
  }

  return Status::OK;
}

Status KatranGrpcService::modifyVip(ServerContext *context,
                                    const VipMeta *request, Bool *response) {

  auto vk = translateVipObject(request->vip());
  Guard lock(giant_);
  auto res = lb_.modifyVip(vk, request->flags(), request->setflag());
  response->set_success(res);
  return returnStatus(res);
}

Status KatranGrpcService::getVipFlags(ServerContext *context,
                                      const Vip *request, Flags *response) {

  int64_t flags = -1;
  auto vk = translateVipObject(*request);

  try {
    Guard lock(giant_);
    flags = lb_.getVipFlags(vk);
  } catch (const std::exception &e) {
    LOG(INFO) << "Exception while getting flags for vip" << e.what();
  }
  response->set_flags(flags);
  return Status::OK;
}

Status KatranGrpcService::addRealForVip(ServerContext *context,
                                        const realForVip *request,
                                        Bool *response) {

  bool res;
  auto vk = translateVipObject(request->vip());
  auto nr = translateRealObject(request->real());
  try {
    Guard lock(giant_);
    res = lb_.addRealForVip(nr, vk);
  } catch (const std::exception &e) {
    res = false;
  }
  response->set_success(res);
  return returnStatus(res);
}

Status KatranGrpcService::delRealForVip(ServerContext *context,
                                        const realForVip *request,
                                        Bool *response) {

  auto vk = translateVipObject(request->vip());
  auto nr = translateRealObject(request->real());
  Guard lock(giant_);
  auto res = lb_.delRealForVip(nr, vk);
  response->set_success(res);
  return returnStatus(res);
}

Status KatranGrpcService::modifyRealsForVip(ServerContext *context,
                                            const modifiedRealsForVip *request,
                                            Bool *response) {

  ::katran::ModifyAction a;
  std::vector<::katran::NewReal> nreals;
  bool res;

  switch (request->action()) {
  case Action::ADD:
    a = ::katran::ModifyAction::ADD;
    break;
  case Action::DEL:
    a = ::katran::ModifyAction::DEL;
    break;
  default:
    break;
  }

  auto vk = translateVipObject(request->vip());
  for (int i = 0; i < request->real().reals_size(); i++) {
    auto nr = translateRealObject(request->real().reals(i));
    nreals.push_back(nr);
  }

  try {
    Guard lock(giant_);
    res = lb_.modifyRealsForVip(a, nreals, vk);
  } catch (const std::exception &e) {
    LOG(INFO) << "Exception while modifying vip: " << e.what();
    res = false;
  }

  response->set_success(res);
  return returnStatus(res);
}

Status KatranGrpcService::getRealsForVip(ServerContext *context,
                                         const Vip *request, Reals *response) {
  //
  Real r;
  std::vector<::katran::NewReal> reals;
  auto vk = translateVipObject(*request);
  try {
    Guard lock(giant_);
    reals = lb_.getRealsForVip(vk);
  } catch (const std::exception &e) {
    LOG(INFO) << "Exception while getting reals from vip: " << e.what();
    return Status::CANCELLED;
  }
  for (auto &real : reals) {
    r.set_address(real.address);
    r.set_weight(real.weight);
    auto rr = response->add_reals();
    *rr = r;
  }
  return Status::OK;
}

Status KatranGrpcService::modifyQuicRealsMapping(
    ServerContext *context, const modifiedQuicReals *request, Bool *response) {

  ::katran::ModifyAction a;
  std::vector<::katran::QuicReal> qreals;
  bool res{true};
  switch (request->action()) {
  case Action::ADD:
    a = ::katran::ModifyAction::ADD;
    break;
  case Action::DEL:
    a = ::katran::ModifyAction::DEL;
    break;
  default:
    break;
  }
  for (int i = 0; i < request->reals().qreals_size(); i++) {
    auto qr = translateQuicRealObject(request->reals().qreals(i));
    qreals.push_back(qr);
  }
  try {
    Guard lock(giant_);
    lb_.modifyQuicRealsMapping(a, qreals);
  } catch (const std::exception &e) {
    LOG(INFO) << "Exception while modifying quic real: " << e.what();
    res = false;
  }
  response->set_success(res);
  return returnStatus(res);
}

Status KatranGrpcService::getQuicRealsMapping(ServerContext *context,
                                              const Empty *request,
                                              QuicReals *response) {

  QuicReal qr;
  std::vector<::katran::QuicReal> qreals;
  try {
    Guard lock(giant_);
    qreals = lb_.getQuicRealsMapping();
  } catch (const std::exception &e) {
    LOG(INFO) << "Exception while getting reals from vip: " << e.what();
    return Status::CANCELLED;
  }
  for (auto &real : qreals) {
    qr.set_address(real.address);
    qr.set_id(real.id);
    auto rqr = response->add_qreals();
    *rqr = qr;
  }

  return Status::OK;
}

Status KatranGrpcService::getStatsForVip(ServerContext *context,
                                         const Vip *request, Stats *response) {

  auto vk = translateVipObject(*request);
  Guard lock(giant_);
  auto stats = lb_.getStatsForVip(vk);

  response->set_v1(stats.v1);
  response->set_v2(stats.v2);

  return Status::OK;
}

Status KatranGrpcService::getLruStats(ServerContext *context,
                                      const Empty *request, Stats *response) {

  Guard lock(giant_);
  auto stats = lb_.getLruStats();

  response->set_v1(stats.v1);
  response->set_v2(stats.v2);

  return Status::OK;
}

Status KatranGrpcService::getLruMissStats(ServerContext *context,
                                          const Empty *request,
                                          Stats *response) {

  Guard lock(giant_);
  auto stats = lb_.getLruMissStats();

  response->set_v1(stats.v1);
  response->set_v2(stats.v2);

  return Status::OK;
}

Status KatranGrpcService::getLruFallbackStats(ServerContext *context,
                                              const Empty *request,
                                              Stats *response) {

  Guard lock(giant_);
  auto stats = lb_.getLruFallbackStats();

  response->set_v1(stats.v1);
  response->set_v2(stats.v2);

  return Status::OK;
}

Status KatranGrpcService::getIcmpTooBigStats(ServerContext *context,
                                             const Empty *request,
                                             Stats *response) {

  Guard lock(giant_);
  auto stats = lb_.getIcmpTooBigStats();

  response->set_v1(stats.v1);
  response->set_v2(stats.v2);

  return Status::OK;
}

Status KatranGrpcService::addHealthcheckerDst(ServerContext *context,
                                              const Healthcheck *request,
                                              Bool *response) {

  if (!hcForwarding_) {
    response->set_success(false);
    return Status::CANCELLED;
  }
  bool res;
  try {
    Guard lock(giant_);
    res = lb_.addHealthcheckerDst(request->somark(), request->address());
  } catch (const std::exception &e) {
    LOG(INFO) << "Exception while adding healthcheck: " << e.what();
    res = false;
  }

  response->set_success(res);
  return returnStatus(res);
}

Status KatranGrpcService::delHealthcheckerDst(ServerContext *context,
                                              const Somark *request,
                                              Bool *response) {

  if (!hcForwarding_) {
    response->set_success(false);
    return Status::CANCELLED;
  }
  Guard lock(giant_);
  auto res = lb_.delHealthcheckerDst(request->somark());
  response->set_success(res);
  return returnStatus(res);
}

Status KatranGrpcService::getHealthcheckersDst(ServerContext *context,
                                               const Empty *request,
                                               hcMap *response) {

  if (!hcForwarding_) {
    return Status::CANCELLED;
  }
  Guard lock(giant_);
  auto hcs = lb_.getHealthcheckersDst();
  auto rhcs = response->mutable_healthchecks();
  for (auto &hc : hcs) {
    (*rhcs)[hc.first] = hc.second;
  }
  return Status::OK;
}

} // namespace katran
} // namespace lb
