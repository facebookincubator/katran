/* Copyright (C) 2019-present, Facebook, Inc.
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

package main

import (
	"flag"
	"fmt"
	"start_katran/affinitize"
	"start_katran/katranc"
	"start_katran/start_binary"
	"start_katran/topology_parser"
	"strconv"
	"strings"
)

var (
	binaryPath = flag.String(
		"binary", "", "Path to katran_grpc_server")
	hcProg = flag.String(
		"hc_bpf", "", "Path to healthchecking bpf prog")
	balancerProg = flag.String(
		"balancer_bpf", "", "Path to balancer bpf prog")
	ipipIntf = flag.String(
		"ipip_intf", "ipip0", "name of the ipip interface for healthchecking")
	ipip6Intf = flag.String(
		"ipip6_intf", "ipip60",
		"name of the ipip6 interface for healthchecking")
	mapPath = flag.String(
		"map_path", "", "path to bpf root array for shared mode")
	progPos = flag.Int(
		"map_pos", 2, "position in shared bpf root array")
	priority = flag.Int(
		"priority", 2307, "priority of healthchecking program")
	shutDelay = flag.Int(
		"shutdown_delay", 1000,
		"sleep timeout before removing xdp prog on shutdown")
	enableHc = flag.Bool(
		"enable_hc", false, "Enable healthchecking bpf prog")
	run = flag.Bool(
		"run", false, "should we run")
	shouldAffinitize = flag.Bool(
		"affinitize", false, "affinitize nic by specified strategy")
	affinitizeOnly = flag.Bool(
		"affinitize_only", false,
		"run only affinitizing logic and exit. do not start katran")
	lruSize = flag.Int(
		"lru_size", 1000000, "size of connection table in entries")
	strategy = flag.Int("strategy",
		affinitize.ALL_NODES,
		"how to affinitize NIC. 0 - sequentaly, 1 - same node, 2 - all nodes")
	intf = flag.String(
		"intf", "enp0s3", "interface where to attach XDP program")
)

func prepareKatranArgs() string {
	cpus := " -forwarding_cores="
	numa := " -numa_nodes="
	forwarding_cpus := affinitize.GetAffinitizeMapping(*intf, *strategy)
	topology := topology_parser.GetCpuTopology()
	numa_nodes := topology.GetNumaListForCpus(forwarding_cpus)
	args := fmt.Sprintf(
		("-balancer_prog=%s -intf=%s -hc_forwarding=%t -map_path=%s" +
			" -prog_pos=%d -ipip_intf=%s -ipip6_intf=%s -priority=%d" +
			" -lru_size=%d -shutdown_delay=%d"),
		*balancerProg,
		*intf,
		*enableHc,
		*mapPath,
		*progPos,
		*ipipIntf,
		*ipip6Intf,
		*priority,
		*lruSize,
		*shutDelay)
	if *enableHc {
		args += (" -healthchecker_prog=" + *hcProg)
	}
	sep := ""
	for _, cpu := range forwarding_cpus {
		cpus = strings.Join([]string{cpus, strconv.Itoa(cpu)}, sep)
		if sep == "" {
			sep = ","
		}
	}
	sep = ""
	for _, node := range numa_nodes {
		numa = strings.Join([]string{numa, strconv.Itoa(node)}, sep)
		if sep == "" {
			sep = ","
		}
	}
	args += cpus
	args += numa
	fmt.Println(args)

	return args
}

func main() {
	flag.Parse()
	if *shouldAffinitize {
		affinitize.AffinitizeIntf(*intf, *strategy)
		if *affinitizeOnly {
			return
		}
	}
	args := prepareKatranArgs()
	var client katranc.KatranClient
	cmd := start_binary.StartKatranArgs{*binaryPath, args}
	if *run {
		start_binary.StartKatran(&client, cmd)
	}
}
