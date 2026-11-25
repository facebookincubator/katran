find_package(fmt CONFIG REQUIRED)
find_package(thrift CONFIG REQUIRED)
find_package(fb303 CONFIG REQUIRED)
find_package(opentelemetry-cpp CONFIG REQUIRED COMPONENTS api sdk exporters_otlp_http)

set(LIBBPF_INCLUDE_DIRS "${BPF_INCLUDEDIR}")
set(LIBBPF_LIBRARIES "${BPF_LINK_LIBRARIES}")
set(BPFOBJECT_VMLINUX_H "${KATRAN_FBCODE_ROOT}/katran/tpr/bpf/vmlinux.h")
set(BPFOBJECT_EXTRA_DEFINES -DKATRAN_CMAKE_BUILD -I${KATRAN_FBCODE_ROOT} -mcpu=v3)
find_package(BpfObject REQUIRED)

bpf_object(katran_de_so_bpf bpf/katran_de_so.bpf.c)
bpf_object(katran_de_tc_bpf bpf/katran_de_tc.bpf.c)

set(KDE_SKEL_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/skel_include")
set(KDE_SKEL_BPF_DIR "${KDE_SKEL_INCLUDE_DIR}/katran/kde/bpf")

add_custom_command(
  OUTPUT "${KDE_SKEL_BPF_DIR}/katran_de_so_bpf.skel.h"
  COMMAND "${CMAKE_COMMAND}" -E make_directory "${KDE_SKEL_BPF_DIR}"
  COMMAND "${CMAKE_COMMAND}" -E copy
    "${CMAKE_CURRENT_BINARY_DIR}/katran_de_so_bpf.skel.h"
    "${KDE_SKEL_BPF_DIR}/katran_de_so_bpf.skel.h"
  DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/katran_de_so_bpf.skel.h"
)

add_custom_command(
  OUTPUT "${KDE_SKEL_BPF_DIR}/katran_de_tc_bpf.skel.h"
  COMMAND "${CMAKE_COMMAND}" -E make_directory "${KDE_SKEL_BPF_DIR}"
  COMMAND "${CMAKE_COMMAND}" -E copy
    "${CMAKE_CURRENT_BINARY_DIR}/katran_de_tc_bpf.skel.h"
    "${KDE_SKEL_BPF_DIR}/katran_de_tc_bpf.skel.h"
  DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/katran_de_tc_bpf.skel.h"
)

add_custom_target(katran_de_bpf_skels
  DEPENDS
    "${KDE_SKEL_BPF_DIR}/katran_de_so_bpf.skel.h"
    "${KDE_SKEL_BPF_DIR}/katran_de_tc_bpf.skel.h"
)

add_library(katran_kde_core STATIC
  core/BaseDirectEncap.cpp
  core/KdeBpfUtil.cpp
  core/ServerDirectEncap.cpp
  core/ClientDirectEncap.cpp
  core/KdeStatsPoller.cpp
  core/KdeStatsOtel.cpp
)
add_dependencies(katran_kde_core katran_de_bpf_skels)
target_include_directories(katran_kde_core PUBLIC
  "${KDE_SKEL_INCLUDE_DIR}"
  ${KATRAN_INCLUDE_DIR}
  ${BPF_INCLUDE_DIRS}
)
target_link_libraries(katran_kde_core PUBLIC
  bpfadapter
  fb303::fb303
  Folly::folly
  fmt::fmt
  glog::glog
  opentelemetry-cpp::api
  opentelemetry-cpp::sdk
  opentelemetry-cpp::otlp_http_metric_exporter
  ${BPF_LINK_LIBRARIES}
)

add_library(katran_kde_api STATIC
  api/DirectEncapApiBase.cpp
  api/DirectEncapClientApi.cpp
  api/DirectEncapServerApi.cpp
)
target_include_directories(katran_kde_api PUBLIC
  ${KATRAN_INCLUDE_DIR}
)
target_link_libraries(katran_kde_api PUBLIC
  katran_kde_core
)

add_library(katran_kde_ctl_lib STATIC
  ctl/KdePinger.cpp
  ctl/KatranDeThrift.cpp
)
target_include_directories(katran_kde_ctl_lib PUBLIC
  ${KATRAN_INCLUDE_DIR}
)
target_link_libraries(katran_kde_ctl_lib PUBLIC
  katran_kde_api
  thrift::rpc
  CLI11::CLI11
)

add_executable(katran_de_ctl
  ctl/katran_de_ctl.cpp
)
target_include_directories(katran_de_ctl PRIVATE
  ${KATRAN_INCLUDE_DIR}
)
target_link_libraries(katran_de_ctl PRIVATE
  katran_kde_ctl_lib
)

install(TARGETS katran_de_ctl
  RUNTIME DESTINATION bin
)

if(BUILD_TESTS)
  katran_add_test(
    TARGET kde_api_test
    SOURCES
      api/test/DirectEncapClientApiTest.cpp
      api/test/DirectEncapServerApiTest.cpp
    DEPENDS
      katran_kde_api
  )
  katran_add_test(
    TARGET kde_cli_parser_test
    SOURCES
      ctl/CliParserTest.cpp
    DEPENDS
      katran_kde_ctl_lib
  )
endif()
