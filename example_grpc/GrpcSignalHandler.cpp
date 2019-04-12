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

#include "GrpcSignalHandler.h"

#include <folly/io/async/EventBase.h>

namespace lb {
namespace katran {

GrpcSignalHandler::GrpcSignalHandler(std::shared_ptr<folly::EventBase> evb,
                                     grpc::Server *server, int32_t delay)
    : folly::AsyncSignalHandler(evb.get()), delay_(delay) {
  server_ = server;
  evb_ = evb;
};

void GrpcSignalHandler::signalReceived(int signum) noexcept {
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
          server_->Shutdown();
        },
        delay_);
  });
  shutdownScheduled_ = true;
};
} // namespace katran
} // namespace lb
