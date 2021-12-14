// Copyright 2004-present Facebook. All Rights Reserved.

#include "katran/lib/EventPipeCallback.h"
#include <folly/Format.h>
#include <folly/Utility.h>
#include <stdint.h>
#include "katran/lib/PcapStructs.h"

namespace katran {
namespace monitoring {

namespace {
constexpr uint32_t kTempBufSize = 4096;
} // namespace

void EventPipeCallback::readBuffer(
    std::unique_ptr<folly::IOBuf>&& buf) noexcept {
  VLOG(4) << __func__ << " ready to send data";
  folly::io::Cursor rcursor(buf.get());
  size_t rec_hdr_sz = sizeof(pcaprec_hdr_s);

  // Here we enter the loop of reading complete pcap records from the buffer. If
  // either the pcap record header or the packet data is incomplete, we break
  // the loop and store whatever is left over in the temporary buffer. Although
  // there are situations where there's no client, the loop has to run in order
  // to maintain bounds between pcap records so that when clients subscribe we
  // can respond without worrying about breaking the bounds between two
  // consecutive pcap records.
  for (;;) {
    pcaprec_hdr_s rec_hdr;
    Event msg;
    if (rcursor.canAdvance(rec_hdr_sz)) {
      rec_hdr = rcursor.read<pcaprec_hdr_s>();
    } else {
      // It's an INFO because when rcursor finishes reading message, this is how
      // we break the loop
      LOG(INFO) << "Can't read rec_hdr_sz, giving up";
      break;
    }

    if (rcursor.canAdvance(rec_hdr.incl_len)) {
      // Back up so that we can include pcap header in data
      rcursor.retreat(rec_hdr_sz);
      msg.id = event_id_;
      msg.pktsize = rec_hdr.orig_len;
      msg.data = std::string(
          reinterpret_cast<const char*>(rcursor.data()),
          rec_hdr_sz + rec_hdr.incl_len);
      rcursor.skip(rec_hdr_sz + rec_hdr.incl_len);
    } else {
      VLOG(2) << folly::format(
          "incomplete pcap message, expecting {} bytes of data, got {}",
          rec_hdr.incl_len,
          rcursor.length());
      rcursor.retreat(rec_hdr_sz);
      break;
    }

    // Send data if the event is enabled
    if (enabled()) {
      auto subsmap = cb_subsmap_.rlock();
      for (auto& it : *subsmap) {
        VLOG(4) << folly::sformat(
            "sending event {} to client", toString(event_id_));
        it.second->sendEvent(msg);
      }
    }
  }

  // Simply triming the amount of bytes we've read. If there's leftover,
  // we should append it to the readBuffer_, which is now empty.
  buf->trimStart(rcursor.getCurrentPosition());
  if (buf->length() != 0) {
    readBuffer_.append(std::move(buf));
  }
}

void EventPipeCallback::addClientSubscription(
    std::pair<ClientId, std::shared_ptr<ClientSubscriptionIf>>&& newSub) {
  ClientId cid = newSub.first;
  VLOG(4) << __func__ << folly::sformat(" Adding client {}", cid);
  auto cb_subsmap = cb_subsmap_.wlock();
  auto result = cb_subsmap->insert(std::move(newSub));
  if (!result.second) {
    LOG(ERROR) << folly::format("duplicate client id: {}", cid);
  }
}

void EventPipeCallback::removeClientSubscription(ClientId cid) {
  auto cb_subsmap = cb_subsmap_.wlock();
  size_t cnt = cb_subsmap->erase(cid);
  if (cnt != 1) {
    LOG(ERROR) << folly::format(
        "no client subscription associated with id: {}", cid);
  }
}

} // namespace monitoring
} // namespace katran
