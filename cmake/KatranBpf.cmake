# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

# katran_bpf_object(<target> SOURCE <file> OUTPUT <name> [DEFINES <flag>...])
#
# Compiles <file> with clang for the BPF target into ${KATRAN_BPF_DIR}/<name>,
# as part of the default build.

find_program(KATRAN_BPF_CLANG clang)
if(NOT KATRAN_BPF_CLANG)
  message(FATAL_ERROR
    "Building katran's BPF programs needs clang. Install it, or configure "
    "with -DKATRAN_BUILD_BPF=OFF.")
endif()
execute_process(
  COMMAND "${KATRAN_BPF_CLANG}" -print-resource-dir
  OUTPUT_VARIABLE KATRAN_BPF_CLANG_RESOURCE_DIR
  OUTPUT_STRIP_TRAILING_WHITESPACE
  COMMAND_ERROR_IS_FATAL ANY
)

set(KATRAN_BPF_DIR "${PROJECT_BINARY_DIR}/bpf")

# The BPF target has no system headers, so the host's follow clang's own.
# glibc's headers choose their variant from the host architecture's macro.
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64)$")
  set(katran_bpf_arch_define -D__x86_64__)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64)$")
  set(katran_bpf_arch_define -D__aarch64__)
endif()
set(katran_bpf_flags
  -target bpf
  -mcpu=v3
  -O2
  -g
  -nostdinc
  ${katran_bpf_arch_define}
  -isystem "${KATRAN_BPF_CLANG_RESOURCE_DIR}/include"
)
# Debian and Ubuntu keep asm/ and glibc's bits/ under a multiarch directory.
if(CMAKE_LIBRARY_ARCHITECTURE)
  list(APPEND katran_bpf_flags
    -idirafter "/usr/include/${CMAKE_LIBRARY_ARCHITECTURE}")
endif()
list(APPEND katran_bpf_flags
  -idirafter /usr/local/include
  -idirafter /usr/include
  -I "${KATRAN_FBCODE_ROOT}"
  -I "${KATRAN_FBCODE_ROOT}/katran/lib/linux_includes"
  -Wno-compare-distinct-pointer-types
)

function(katran_bpf_object target)
  cmake_parse_arguments(PARSE_ARGV 1 ARG "" "SOURCE;OUTPUT" "DEFINES")
  set(output "${KATRAN_BPF_DIR}/${ARG_OUTPUT}")
  add_custom_command(
    OUTPUT "${output}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${KATRAN_BPF_DIR}"
    COMMAND "${KATRAN_BPF_CLANG}" ${katran_bpf_flags} ${ARG_DEFINES}
            -MD -MF "${output}.d"
            -c "${CMAKE_CURRENT_SOURCE_DIR}/${ARG_SOURCE}" -o "${output}"
    DEPENDS "${ARG_SOURCE}"
    DEPFILE "${output}.d"
    COMMENT "Building BPF object ${ARG_OUTPUT}"
    VERBATIM
  )
  add_custom_target(${target} ALL DEPENDS "${output}")
endfunction()

# katran_add_bpf_test(<name> <command>...)
#
# <command> runs BPF programs in the kernel's test runner, which needs root, so
# ctest skips it otherwise: `sudo ctest -L bpf` runs these. The katran testers
# exit 0 even when a fixture fails, so their per-packet result lines decide.
# Their counter checks fail even when every fixture passes, so they don't.
function(katran_add_bpf_test name)
  add_test(NAME ${name}
    COMMAND sh -c [=[if [ "$(id -u)" -ne 0 ]; then echo "needs root: sudo ctest -L bpf"; exit 77; fi; exec "$@"]=]
            sh ${ARGN}
  )
  set_tests_properties(${name} PROPERTIES
    LABELS bpf
    SKIP_RETURN_CODE 77
    FAIL_REGULAR_EXPRESSION "result: [^\n]*Failed"
  )
endfunction()
