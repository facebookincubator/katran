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

#include "XdpEventReader.h"

#include <bcc/libbpf.h>
#include <folly/String.h>
#include <folly/io/async/EventBase.h>
#include <unistd.h>

#include "PcapWriter.h"

extern "C" {
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/types.h>
}

namespace xdpdump {

namespace {

struct perf_event_sample {
  struct perf_event_header header;
  __u32 size;
  char data[];
};

int perf_event_open(struct perf_event_attr *attr, int pid, int cpu,
                    int group_fd, unsigned long flags) {
  return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

int get_perf_event_fd(int cpu, int wakeUpNumEvents) {
  struct perf_event_attr attr;
  int pmu_fd;
  ::memset(&attr, 0, sizeof(attr));
  attr.sample_type = PERF_SAMPLE_RAW;
  attr.type = PERF_TYPE_SOFTWARE;
  attr.config = PERF_COUNT_SW_BPF_OUTPUT;
  if (wakeUpNumEvents) {
    attr.sample_period = wakeUpNumEvents;
    attr.wakeup_events = wakeUpNumEvents;
  }

  pmu_fd = perf_event_open(&attr, -1, cpu, -1, 0);

  if (pmu_fd < 0) {
    LOG(ERROR) << "bpf_perf_event_open failed";
    return pmu_fd;
  }

  if (::ioctl(pmu_fd, PERF_EVENT_IOC_ENABLE, 0)) {
    LOG(ERROR) << "cannot open perf event for cpu:" << cpu << ". "
               << folly::errnoStr(errno);
    close(pmu_fd);
    pmu_fd = -1;
  }
  return pmu_fd;
}

struct perf_event_mmap_page *FOLLY_NULLABLE mmap_perf_event(int fd, int pages) {
  if (fd < 0) {
    LOG(ERROR) << "Won't mmap for fd < 0";
    return nullptr;
  }

  auto mmap_size = ::getpagesize() * (pages + 1);
  auto base =
      ::mmap(nullptr, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (base == MAP_FAILED) {
    LOG(ERROR) << "cannot mmap perf event. " << folly::errnoStr(errno);
    return nullptr;
  }

  return reinterpret_cast<struct perf_event_mmap_page *>(base);
}

bool perfEventUnmmap(struct perf_event_mmap_page **header, int pages) {
  bool ret = false;
  if (header != nullptr && *header != nullptr) {
    auto res = ::munmap(*header, pages * ::getpagesize() + 1);
    if (!res) {
      *header = nullptr;
      ret = true;
    }
  }
  return ret;
}

bool openPerfEvent(int cpu, int map_fd, int wakeUpNumEvents, int pages,
                   struct perf_event_mmap_page **header, int &event_fd) {
  if (header == nullptr || *header != nullptr) {
    LOG(ERROR) << "Won't open perf event with header not equal to nullptr";
    return false;
  }
  event_fd = get_perf_event_fd(cpu, wakeUpNumEvents);
  if (event_fd < 0) {
    LOG(ERROR) << "Failed to get perf event fd";
    return false;
  }
  *header = mmap_perf_event(event_fd, pages);
  if (*header == nullptr) {
    return false;
  }
  if (bpf_update_elem(map_fd, &cpu, &event_fd, BPF_ANY)) {
    LOG(ERROR) << "failed to update perf_event_map " << folly::errnoStr(errno);
    return false;
  }
  return true;
}

void perfEventHandler(
    folly::Function<void(const char *data, size_t size)> eventHandler,
    struct perf_event_mmap_page *header, std::string &buffer, int pageSize,
    int pages, int cpu) {
  if (header == nullptr) {
    VLOG(2) << "handlePerfEvent: unexpectedly header equals to nullptr";
    return;
  }
  auto dataTail = header->data_tail;
  auto dataHead = header->data_head;
  auto bufferSize = pageSize * pages;
  char *base, *begin, *end;

  asm volatile("" ::: "memory"); /* smp_rmb() */
  if (dataHead == dataTail) {
    return;
  }

  base = reinterpret_cast<char *>(header) + pageSize;

  begin = base + dataTail % bufferSize;
  end = base + dataHead % bufferSize;

  while (begin != end) {
    const struct perf_event_sample *event;

    event = reinterpret_cast<const struct perf_event_sample *>(begin);
    if (begin + event->header.size > base + bufferSize) {
      long len = base + bufferSize - begin;

      CHECK_LT(len, event->header.size);
      if (event->header.size > buffer.size()) {
        buffer.resize(event->header.size);
      }
      buffer.assign(begin, len);
      buffer.insert(len, base, event->header.size - len);
      event = reinterpret_cast<const struct perf_event_sample *>(buffer.data());
      begin = base + event->header.size - len;
    } else if (begin + event->header.size == base + bufferSize) {
      begin = base;
    } else {
      begin += event->header.size;
    }

    if (event->header.type == PERF_RECORD_SAMPLE) {
      eventHandler(event->data, event->size);
    } else if (event->header.type == PERF_RECORD_LOST) {
      const struct lost_sample {
        struct perf_event_header header;
        __u64 id;
        __u64 lost;
      } *lost = reinterpret_cast<const struct lost_sample *>(event);
      VLOG(5) << "cpu:" << cpu << " lost " << lost->lost << " events";
    } else {
      VLOG(5) << "cpu:" << cpu
              << " received unknown event type:" << event->header.type
              << " size:" << event->header.size;
    }
  }
  __sync_synchronize(); /* smp_mb() */
  header->data_tail = dataHead;
}

} // namespace

XdpEventReader::XdpEventReader(std::shared_ptr<folly::MPMCQueue<PcapMsg>> queue,
                               std::shared_ptr<XdpEventLogger> eventLogger,
                               int pages, int cpu)
    : queue_(queue), eventLogger_(eventLogger), pages_(pages), cpu_(cpu) {
  pageSize_ = ::getpagesize();
}

XdpEventReader::~XdpEventReader() { perfEventUnmmap(&header_, pages_); }

bool XdpEventReader::open(int eventMapFd, folly::EventBase *evb,
                          int wakeUpNumEvents) {
  int fd;
  if (!openPerfEvent(cpu_, eventMapFd, wakeUpNumEvents, pages_, &header_, fd)) {
    LOG(ERROR) << "can't open perf event for map with fd: " << eventMapFd;
    return false;
  }
  initHandler(evb, folly::NetworkSocket::fromFd(fd));
  if (!registerHandler(READ | PERSIST)) {
    LOG(ERROR) << "can't register XdpEventReader for read event";
    return false;
  }
  return true;
}

void XdpEventReader::handlerReady(uint16_t /* events */) noexcept {
  perfEventHandler(
      [this](const char *data, size_t size) { handlePerfEvent(data, size); },
      header_, buffer_, pageSize_, pages_, cpu_);
}

void XdpEventReader::handlePerfEvent(const char *data,
                                     size_t /* unused */) noexcept {
  auto info = eventLogger_->handlePerfEvent(data);
  if (queue_ != nullptr) {
    PcapMsg pcap_msg(data + info.hdr_size, info.pkt_size, info.data_len);
    // best effort non blocking write. if writer thread is full we will lose
    // this packet
    auto res = queue_->write(std::move(pcap_msg));
    if (!res) {
      // queue is full and we wasnt able to write into it.
      ++queueFull_;
    }
  }
}

} // namespace xdpdump
