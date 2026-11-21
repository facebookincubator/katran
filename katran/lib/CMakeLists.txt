add_library(murmur3 STATIC
    MurmurHash3.h
    MurmurHash3.cpp
)

add_library(chhelpers STATIC
    CHHelpers.h
    CHHelpers.cpp
    MaglevBase.h
    MaglevBase.cpp
    MaglevHash.h
    MaglevHash.cpp
    MaglevHashV2.h
    MaglevHashV2.cpp
)

target_link_libraries(chhelpers murmur3)

target_include_directories(
  chhelpers PUBLIC
  ${KATRAN_INCLUDE_DIR}
)

add_library(iphelpers STATIC
    IpHelpers.h
    IpHelpers.cpp
)

target_link_libraries(iphelpers
    Folly::folly
    "glog::glog"
    ${LIBGFLAGS_LIBRARY}
)

target_include_directories(
  iphelpers PUBLIC
  ${KATRAN_INCLUDE_DIR}
)

add_library(bpfadapter STATIC
    BaseBpfAdapter.cpp
    BaseBpfAdapter.h
    BpfAdapter.cpp
    BpfLoader.cpp
    BpfAdapter.h
    BpfLoader.h
    Netlink.cpp
    Netlink.h
    linux_includes/bpf.h
    linux_includes/bpf_common.h
    linux_includes/bpf_helpers.h
)

target_link_libraries(bpfadapter
  PUBLIC
    ${BPF_LINK_LIBRARIES}
    ${LIBELF_LINK_LIBRARIES}
    ${ZLIB_LIBRARIES}
    ${ZSTD_LINK_LIBRARIES}
    ${LIBMNL_LINK_LIBRARIES}
    glog::glog
    Threads::Threads
    Folly::folly
)

target_include_directories(
  bpfadapter PUBLIC
  ${BPF_INCLUDE_DIRS}
  ${KATRAN_INCLUDE_DIR}
  ${LIBMNL_INCLUDE_DIRS}
)

add_library(pcapwriter STATIC
    ByteRangeWriter.cpp
    FileWriter.cpp
    IOBufWriter.cpp
    PipeWriter.cpp
    PcapMsg.cpp
    PcapMsgMeta.cpp
    PcapWriter.cpp
    MonitoringStructs.cpp
    ByteRangeWriter.h
    IOBufWriter.h
    DataWriter.h
    FileWriter.h
    PipeWriter.h
    PcapMsg.h
    PcapMsgMeta.h
    PcapStructs.h
    PcapWriter.h
    MonitoringStructs.h
)

set(PCAPWRITER_DEPS
    "-Wl,--start-group"
    glog::glog
    Threads::Threads
    ${ZLIB_LIBRARIES}
    Folly::folly
    "-Wl,--end-group"
)

target_link_libraries(pcapwriter "${PCAPWRITER_DEPS}")

add_library(katransimulator STATIC
  KatranSimulator.h
  KatranSimulator.cpp
  KatranSimulatorUtils.h
  KatranSimulatorUtils.cpp
)

add_dependencies(
  katransimulator
  bpfadapter
)

target_link_libraries(katransimulator
    bpfadapter
)

target_include_directories(
  pcapwriter PUBLIC
  ${KATRAN_INCLUDE_DIR}
)

add_library(katranlb STATIC
    KatranEventReader.h
    KatranEventReader.cpp
    KatranMonitor.h
    KatranMonitor.cpp
    KatranLb.h
    KatranLb.cpp
    KatranLbStructs.h
    BalancerStructs.h
    Vip.h
    Vip.cpp
    EventPipeCallback.h
    EventPipeCallback.cpp
    MonitoringServiceCore.h
    MonitoringServiceCore.cpp
    PerfBufferEventReader.h
    PerfBufferEventReader.cpp
)

target_link_libraries(katranlb
    "-Wl,--start-group"
    bpfadapter
    chhelpers
    iphelpers
    pcapwriter
    katransimulator
    ${LIBGFLAGS_LIBRARY}
    Threads::Threads
    "-Wl,--end-group"
)

target_include_directories(
  katranlb PUBLIC
  ${BPF_INCLUDE_DIRS}
  ${KATRAN_INCLUDE_DIR}
)

add_library(mac_helpers STATIC
    MacHelpers.h
    MacHelpers.cpp
)

target_link_libraries(mac_helpers
    Folly::folly
    glog::glog
)

target_include_directories(
  mac_helpers PUBLIC
  ${KATRAN_INCLUDE_DIR}
)

add_executable(xdproot xdproot.cpp)

target_link_libraries(xdproot
  PUBLIC
    bpfadapter
    ${LIBGFLAGS_LIBRARY}
)

target_include_directories(
  xdproot PUBLIC
  ${LIBGFLAGS_INCLUDE_DIR}
  ${KATRAN_INCLUDE_DIR}
)

add_executable(maglev_integration_test maglev_integration_test.cpp)

target_link_libraries(maglev_integration_test
    chhelpers
    ${LIBGFLAGS_LIBRARY}
    Threads::Threads
)

target_include_directories(
  maglev_integration_test PUBLIC
  ${LIBGFLAGS_INCLUDE_DIR}
  ${KATRAN_INCLUDE_DIR}
)

file(
  GLOB_RECURSE KATRAN_HEADERS_TOINSTALL
  RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
  *.h
)
list(FILTER KATRAN_HEADERS_TOINSTALL EXCLUDE REGEX tests/)
foreach(header ${KATRAN_HEADERS_TOINSTALL})
  get_filename_component(header_dir ${header} DIRECTORY)
  install(FILES ${header} DESTINATION include/katran/lib/${header_dir})
endforeach()

install(
  TARGETS murmur3
  EXPORT katran-exports
  DESTINATION lib
)

install(
  TARGETS chhelpers
  EXPORT katran-exports
  DESTINATION lib
)

install(
  TARGETS iphelpers
  EXPORT katran-exports
  DESTINATION lib
)

install(
  TARGETS bpfadapter
  EXPORT katran-exports
  DESTINATION lib
)

install(
  TARGETS pcapwriter
  EXPORT katran-exports
  DESTINATION lib
)

install(
  TARGETS katransimulator
  EXPORT katran-exports
  DESTINATION lib
)

install(
  TARGETS katranlb
  EXPORT katran-exports
  DESTINATION lib
)

install(
  TARGETS mac_helpers
  EXPORT katran-exports
  DESTINATION lib
)

if (KATRAN_BUILD_BPF)
  add_subdirectory(bpf)
endif()

if (BUILD_TESTS)
  add_subdirectory(testing)
  add_subdirectory(tests)
endif()
