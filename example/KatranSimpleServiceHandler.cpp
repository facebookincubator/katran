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


#include "KatranSimpleServiceHandler.h"

#include <cstdint>

#include "katran/lib/MacHelpers.h"

namespace lb {
namespace katran {

using Guard = std::lock_guard<std::mutex>;

// some helper for most common translations
::katran::VipKey translateVipObject(const Vip& vip) {
  ::katran::VipKey vk;
  vk.address = vip.address;
  vk.port = vip.port;
  vk.proto = vip.protocol;
  return vk;
}

::katran::NewReal translateRealObject(const Real& real) {
  ::katran::NewReal nr;
  nr.address = real.address;
  nr.weight = real.weight;
  return nr;
}

::katran::QuicReal translateQuicRealObject(const QuicReal& real) {
  ::katran::QuicReal qr;
  qr.address = real.address;
  qr.id = real.id;
  return qr;
}

KatranSimpleServiceHandler::KatranSimpleServiceHandler(
    const ::katran::KatranConfig& config)
    : lb_(config), hcForwarding_(config.enableHc) {
  lb_.loadBpfProgs();
  lb_.attachBpfProgs();
}

bool KatranSimpleServiceHandler::changeMac(
    std::unique_ptr<::lb::katran::Mac> newMac) {
  Guard lock(giant_);
  auto mac = ::katran::convertMacToUint(newMac->mac);
  return lb_.changeMac(mac);
}

void KatranSimpleServiceHandler::getMac(::lb::katran::Mac& _return) {
  Guard lock(giant_);
  auto mac = lb_.getMac();
  _return.mac = ::katran::convertMacToString(mac);
  return;
}

bool KatranSimpleServiceHandler::addVip(
    std::unique_ptr<::lb::katran::VipMeta> vipMeta) {
  bool res;
  auto vk = translateVipObject(vipMeta->vip);

  try {
    Guard lock(giant_);
    res = lb_.addVip(vk, vipMeta->flags);
  } catch (const std::exception& e) {
    LOG(INFO) << "Exception while adding new vip: " << e.what();
    res = false;
  }
  return res;
}

bool KatranSimpleServiceHandler::delVip(
    std::unique_ptr<::lb::katran::Vip> vip) {
  auto vk = translateVipObject(*vip.get());
  Guard lock(giant_);
  return lb_.delVip(vk);
}

void KatranSimpleServiceHandler::getAllVips(
    std::vector<::lb::katran::Vip>& _return) {
  lb::katran::Vip vip;
  Guard lock(giant_);
  auto vips = lb_.getAllVips();
  for (auto& v : vips) {
    vip.address = v.address;
    vip.port = v.port;
    vip.protocol = v.proto;
    _return.push_back(vip);
  }
  return;
}

bool KatranSimpleServiceHandler::modifyVip(
    std::unique_ptr<::lb::katran::VipMeta> vipMeta) {
  auto vk = translateVipObject(vipMeta->vip);
  Guard lock(giant_);
  return lb_.modifyVip(vk, vipMeta->flags, vipMeta->setFlag);
}

int64_t KatranSimpleServiceHandler::getVipFlags(
    std::unique_ptr<::lb::katran::Vip> vip) {
  int64_t flags = -1;
  auto vk = translateVipObject(*vip.get());

  try {
    Guard lock(giant_);
    flags = lb_.getVipFlags(vk);
  } catch (const std::exception& e) {
    LOG(INFO) << "Exception while getting flags for vip" << e.what();
  }
  return flags;
}

bool KatranSimpleServiceHandler::addRealForVip(
    std::unique_ptr<::lb::katran::Real> real,
    std::unique_ptr<::lb::katran::Vip> vip) {
  bool res;
  auto vk = translateVipObject(*vip.get());
  auto nr = translateRealObject(*real.get());
  try {
    Guard lock(giant_);
    res = lb_.addRealForVip(nr, vk);
  } catch (const std::exception& e) {
    res = false;
  }
  return res;
}

bool KatranSimpleServiceHandler::delRealForVip(
    std::unique_ptr<::lb::katran::Real> real,
    std::unique_ptr<::lb::katran::Vip> vip) {
  auto vk = translateVipObject(*vip.get());
  auto nr = translateRealObject(*real.get());
  Guard lock(giant_);
  return lb_.delRealForVip(nr, vk);
}

bool KatranSimpleServiceHandler::modifyRealsForVip(
    ::lb::katran::Action action,
    std::unique_ptr<::lb::katran::Reals> reals,
    std::unique_ptr<::lb::katran::Vip> vip) {
  ::katran::ModifyAction a;
  std::vector<::katran::NewReal> nreals;
  bool res;

  switch (action) {
    case Action::ADD:
      a = ::katran::ModifyAction::ADD;
      break;
    case Action::DEL:
      a = ::katran::ModifyAction::DEL;
      break;
  }

  auto vk = translateVipObject(*vip.get());
  for (auto& real : *reals.get()) {
    auto nr = translateRealObject(real);
    nreals.push_back(nr);
  }

  try {
    Guard lock(giant_);
    res = lb_.modifyRealsForVip(a, nreals, vk);
  } catch (const std::exception& e) {
    LOG(INFO) << "Exception while modifying vip: " << e.what();
    res = false;
  }

  return res;
}

void KatranSimpleServiceHandler::getRealsForVip(
    ::lb::katran::Reals& _return,
    std::unique_ptr<::lb::katran::Vip> vip) {
  Real r;
  std::vector<::katran::NewReal> reals;
  auto vk = translateVipObject(*vip.get());
  try {
    Guard lock(giant_);
    reals = lb_.getRealsForVip(vk);
  } catch (const std::exception& e) {
    LOG(INFO) << "Exception while getting reals from vip: " << e.what();
    return;
  }
  for (auto& real : reals) {
    r.address = real.address;
    r.weight = real.weight;
    _return.push_back(r);
  }
  return;
}

bool KatranSimpleServiceHandler::modifyQuicRealsMapping(
    ::lb::katran::Action action,
    std::unique_ptr<::lb::katran::QuicReals> reals) {
  ::katran::ModifyAction a;
  std::vector<::katran::QuicReal> qreals;
  bool res{true};
  switch (action) {
    case Action::ADD:
      a = ::katran::ModifyAction::ADD;
      break;
    case Action::DEL:
      a = ::katran::ModifyAction::DEL;
      break;
  }
  for (auto& real : *reals) {
    auto qr = translateQuicRealObject(real);
    qreals.push_back(qr);
  }
  try {
    Guard lock(giant_);
    lb_.modifyQuicRealsMapping(a, qreals);
  } catch (const std::exception& e) {
    LOG(INFO) << "Exception while modifying quic real: " << e.what();
    res = false;
  }
  return res;
}

void KatranSimpleServiceHandler::getQuicRealsMapping(
    ::lb::katran::QuicReals& _return) {
  QuicReal qr;
  std::vector<::katran::QuicReal> qreals;
  try {
    Guard lock(giant_);
    qreals = lb_.getQuicRealsMapping();
  } catch (const std::exception& e) {
    LOG(INFO) << "Exception while getting reals from vip: " << e.what();
    return;
  }
  for (auto& real : qreals) {
    qr.address = real.address;
    qr.id = real.id;
    _return.push_back(qr);
  }
  return;
}

void KatranSimpleServiceHandler::getStatsForVip(
    ::lb::katran::Stats& _return,
    std::unique_ptr<::lb::katran::Vip> vip) {
  auto vk = translateVipObject(*vip.get());
  Guard lock(giant_);
  auto stats = lb_.getStatsForVip(vk);

  _return.v1 = stats.v1;
  _return.v2 = stats.v2;
}

void KatranSimpleServiceHandler::getLruStats(::lb::katran::Stats& _return) {
  Guard lock(giant_);
  auto stats = lb_.getLruStats();

  _return.v1 = stats.v1;
  _return.v2 = stats.v2;
}

void KatranSimpleServiceHandler::getLruMissStats(::lb::katran::Stats& _return) {
  Guard lock(giant_);
  auto stats = lb_.getLruMissStats();

  _return.v1 = stats.v1;
  _return.v2 = stats.v2;
}

void KatranSimpleServiceHandler::getLruFallbackStats(
    ::lb::katran::Stats& _return) {
  Guard lock(giant_);
  auto stats = lb_.getLruFallbackStats();

  _return.v1 = stats.v1;
  _return.v2 = stats.v2;
}

void KatranSimpleServiceHandler::getIcmpTooBigStats(
    ::lb::katran::Stats& _return) {
  Guard lock(giant_);
  auto stats = lb_.getIcmpTooBigStats();

  _return.v1 = stats.v1;
  _return.v2 = stats.v2;
}

bool KatranSimpleServiceHandler::addHealthcheckerDst(
    std::unique_ptr<::lb::katran::Healthcheck> healthcheck) {
  if (!hcForwarding_) {
    return false;
  }
  bool res;
  try {
    Guard lock(giant_);
    res = lb_.addHealthcheckerDst(healthcheck->somark, healthcheck->address);
  } catch (const std::exception& e) {
    LOG(INFO) << "Exception while adding healthcheck: " << e.what();
    res = false;
  }
  return res;
}

bool KatranSimpleServiceHandler::delHealthcheckerDst(int32_t somark) {
  if (!hcForwarding_) {
    return false;
  }
  Guard lock(giant_);
  return lb_.delHealthcheckerDst(somark);
}

void KatranSimpleServiceHandler::getHealthcheckersDst(
    ::lb::katran::hcMap& _return) {
  if (!hcForwarding_) {
    return;
  }
  Guard lock(giant_);
  auto hcs = lb_.getHealthcheckersDst();
  for (auto& hc : hcs) {
    _return[hc.first] = hc.second;
  }
  return;
}

} // namespace katran
} // namespace lb
