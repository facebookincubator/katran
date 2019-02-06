cmake_minimum_required(VERSION 3.9)
project(xdpdump)
set (CMAKE_CXX_STANDARD 14)

find_library(LIBBCC bcc)
find_library(DL dl)
find_library(LIBIBERTY libiberty.a iberty)
find_library(EVENT libevent.a event)
find_library(EVENT_CORE libevent_core.a event_core)

add_library(pcap_writer
  PcapWriter.h
  PcapStructs.h
  PcapWriter.cpp
  PcapMsg.h
  PcapMsg.cpp
)

target_link_libraries(pcap_writer
  "${FOLLY}"
)

add_library(xdp_event_logger
  XdpEventLogger.h
  XdpEventReader.h
  XdpEventReader.cpp
  XdpEventLogger.cpp
)

target_link_libraries(xdp_event_logger
  pcap_writer
  "${FOLLY}"
  "${GLOG}"
)

add_library(lxdpdump
  XdpDump.h
  XdpDump.cpp
  XdpDumpKern.h
)

target_link_libraries(lxdpdump
  xdp_event_logger
  "${LIBELF}"
  "${LIBZ}"
  "${LIBBCC}"
  "${FOLLY}"
  "${GLOG}"
)

add_executable(xdpdump xdpdump_tool.cpp)
target_link_libraries(xdpdump
  "-Wl,--start-group"
  "${LIBUNWIND}"
  "${LIBLZMA}"
  "${FOLLY}"
  "${GLOG}"
  "${GFLAGS}"
  "${PTHREAD}"
  "${LIBDC}"
  "${DL}"
  "${EVENT}"
  "${EVENT_CORE}"
  "${LIBIBERTY}"
  iphelpers
  lxdpdump
  "-Wl,--end-group"
)
