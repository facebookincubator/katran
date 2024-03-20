cmake_minimum_required(VERSION 3.9)
project(xdpdump)
set (CMAKE_CXX_STANDARD 17)

find_library(LIBBCC bcc)
find_library(DL dl)
find_library(LIBIBERTY libiberty.a iberty)
find_library(EVENT_CORE libevent_core.a event_core)

add_library(xdp_event_logger
  XdpEventLogger.h
  XdpEventReader.h
  XdpEventReader.cpp
  XdpEventLogger.cpp
)

target_link_libraries(xdp_event_logger
  katranlb
  pcapwriter
  "Folly::folly"
  "glog::glog"
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
  "Folly::folly"
  "glog::glog"
)

add_executable(xdpdump xdpdump_tool.cpp)
target_link_libraries(xdpdump
  "-Wl,--start-group"
  "${LIBUNWIND}"
  "Folly::folly"
  "glog::glog"
  "${GFLAGS}"
  "${PTHREAD}"
  "${LIBDC}"
  "${DL}"
  "${EVENT_CORE}"
  "${LIBIBERTY}"
  iphelpers
  lxdpdump
  "-Wl,--end-group"
)
