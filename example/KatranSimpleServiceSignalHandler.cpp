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

#include "KatranSimpleServiceSignalHandler.h"

#include <thrift/lib/cpp2/server/ThriftServer.h>

namespace lb {
namespace katran {

KatranSimpleServiceSignalHandler::KatranSimpleServiceSignalHandler(
    folly::EventBase* evb,
    apache::thrift::ThriftServer* service,
    int32_t delay)
    : folly::AsyncSignalHandler(evb), delay_(delay) {
  service_ = service;
  evb_ = evb;
};

void KatranSimpleServiceSignalHandler::signalReceived(int signum) noexcept {
  if (shutdownScheduled_) {
    LOG(INFO) << "Ignoring signal: " << signum << " as we already scheduled"
              << " sighandler to run.";
    return;
  };
  LOG(INFO) << "Signal: " << signum << ", stopping service in " << delay_
            << " milliseconds.";
  evb_->runInEventBaseThread([this]() {
    evb_->runAfterDelay(
        [this]() {
          LOG(INFO) << "Stopping Katran!";
          service_->stop();
        },
        delay_);
  });
  shutdownScheduled_ = true;
};

} // namespace katran
} // namespace lb
