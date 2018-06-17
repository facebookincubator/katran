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

#include <folly/io/async/EventBase.h>
#include <folly/io/async/ScopedEventBaseThread.h>
#include <vector>

#include "katran/if/gen-cpp2/KatranServiceAsyncClient.h"

namespace lb {
namespace katran {

/**
 * Simple example of libkatran usage as client.
 * The client establishes connection to katran thrift server in the given
 * address and port during its initialization, and makes calls to the server
 * for all the necessary 'L4' work (e.g. addVips, removeVips and so on).
 * In this example the client makes blocking (sync) calls to the thrift server.
 * See https://github.com/facebook/fbthrift/blob/master/thrift/doc/Cpp2.md on
 * how to do so asynchronously.
 */
class KatranSimpleClient {
public:
  KatranSimpleClient() = delete;

  explicit KatranSimpleClient(const std::string &host, int port = 12307);

  ~KatranSimpleClient() = default;

  void changeMac(const std::string &mac);

  void getMac();

  void addOrModifyService(const std::string &address, const std::string &flags,
                          int proto, bool modify, bool setFlags);

  void delService(const std::string &address, int proto);

  void updateService(Vip &vip, uint64_t flags, Action action, bool setFlags);

  void updateServerForVip(const std::string &vipAddr, int proto,
                          const std::string &realAddr, uint64_t weight,
                          bool del);

  void modifyQuicMappings(const std::string &mapping, bool del);

  std::vector<::lb::katran::Vip> getAllVips();

  hcMap getAllHcs();

  Reals getRealsForVip(const Vip &vip);

  uint64_t getFlags(const Vip &Vip);

  void listVipAndReals(const Vip &vip);

  void list(const std::string &address, int proto);

  void clearAll();

  void listQm();

  void addHc(const std::string &address, uint32_t somark);

  void delHc(uint32_t somark);

  void listHc();

  void showSumStats();

  void showLruStats();

  void showPerVipStats();

  void showIcmpStats();

private:
  Vip parseToVip(const std::string &address, uint32_t protocol);

  Real parseToReal(const std::string &address, uint32_t weight);

  QuicReal parseToQuicReal(const std::string &mapping);

  std::string parseFlags(uint64_t flags);

  // factory method to create KatranServiceClient instance
  std::unique_ptr<KatranServiceAsyncClient>
  createKatranClient(const folly::SocketAddress &addr);

  std::string host_;
  int port_;
  folly::EventBase evb_;
  std::unique_ptr<KatranServiceAsyncClient> client_;
};

} // namespace katran
} // namespace lb
