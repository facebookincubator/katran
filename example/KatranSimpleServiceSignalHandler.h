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

#include <folly/io/async/AsyncSignalHandler.h>
#include <folly/io/async/EventBase.h>

namespace apache {
namespace thrift {

class ThriftServer;
}
} // namespace apache

namespace lb {
namespace katran {

/**
 * class which implements sighandler for katran's thrift server
 */
class KatranSimpleServiceSignalHandler : public folly::AsyncSignalHandler {
 public:
  /**
   * @param EventBase* evb event base thread
   * @param ServiceFramework* service katran's thrift server
   * @param int32_t delay in ms between recving signal and stopping katran
   */
  KatranSimpleServiceSignalHandler(
      folly::EventBase* evb,
      apache::thrift::ThriftServer* service,
      int32_t delay);
  ~KatranSimpleServiceSignalHandler() override {}

  void signalReceived(int signum) noexcept override;

 private:
  apache::thrift::ThriftServer* service_;
  folly::EventBase* evb_;
  int32_t delay_;
  bool shutdownScheduled_{false};
};

} // namespace katran
} // namespace lb
