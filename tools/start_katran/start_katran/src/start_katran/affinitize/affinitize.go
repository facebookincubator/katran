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

package affinitize

import (
	"fmt"
	"io/ioutil"
	"log"
	"start_katran/irq_parser"
	"start_katran/topology_parser"
	"strconv"
)

const (
	IRQ_DIR         string = "/proc/irq/"
	IRQ_FILE_SUFFIX string = "/smp_affinity"
)

// affinitizing strategy.
const (
	SEQ_NODES int = iota
	SAME_NODE
	ALL_NODES
)

// which numa node to use for same numa node strategy
const (
	NUMA_NODE int = 0
)

// array of cpus is small and we do this only on startup.
// so no point to make anything complex here
func searchSlice(i int, s []int) bool {
	for _, v := range s {
		if v == i {
			return true
		}
	}
	return false
}

func writeAffinityToFile(irq int, cpu uint64, ncpus int) {
	mask := make([]string, ncpus/32+1, ncpus/32+1)
	for i, _ := range mask {
		mask[i] = "00000000"
	}
	mask[cpu/32] = fmt.Sprintf("%08x", 1<<(cpu%32))
	cpu_flag_str := mask[len(mask)-1]
	for i := len(mask) - 2; i >= 0; i-- {
		cpu_flag_str += ("," + mask[i])
	}
	irq_str := strconv.Itoa(irq)
	log.Printf("affinitizing irq %d to cpu %d mask %s\n",
		irq, cpu, cpu_flag_str)
	filename := IRQ_DIR + irq_str + IRQ_FILE_SUFFIX
	err := ioutil.WriteFile(filename, []byte(cpu_flag_str), 0644)
	if err != nil {
		log.Fatal("error while writing affinitiy for irq and cpu:",
			irq, cpu, err)
	}
}

func affinitizeSeqNodes(intf string, write bool) []int {
	var forwarding_cpus []int
	irqs := irq_parser.GetInterfaceIrq(intf)
	topo := topology_parser.GetCpuTopology()
	for i, irq := range irqs {
		cpu := i % topo.Ncpus
		if !searchSlice(cpu, forwarding_cpus) {
			forwarding_cpus = append(forwarding_cpus, cpu)
		}
		if write {
			writeAffinityToFile(irq, uint64(cpu), topo.Ncpus)
		}
	}
	return forwarding_cpus
}

func affinitizeSameNode(intf string, write bool) []int {
	var forwarding_cpus []int
	irqs := irq_parser.GetInterfaceIrq(intf)
	topo := topology_parser.GetCpuTopology()
	for i, irq := range irqs {
		cpu_idx := i % len(topo.Numa2Cpu[NUMA_NODE])
		cpu := topo.Numa2Cpu[NUMA_NODE][cpu_idx]
		if !searchSlice(cpu, forwarding_cpus) {
			forwarding_cpus = append(forwarding_cpus, cpu)
		}
		if write {
			writeAffinityToFile(irq, uint64(cpu), topo.Ncpus)
		}
	}
	return forwarding_cpus
}

func affinitizeAllNodes(intf string, write bool) []int {
	var forwarding_cpus []int
	irqs := irq_parser.GetInterfaceIrq(intf)
	topo := topology_parser.GetCpuTopology()
	for i, irq := range irqs {
		numa_idx := i % len(topo.Numa2Cpu)
		// assumption that all numa nodes has same number of cpus
		cpu_idx := (i / len(topo.Numa2Cpu)) % len(topo.Numa2Cpu[NUMA_NODE])
		cpu := topo.Numa2Cpu[numa_idx][cpu_idx]
		if !searchSlice(cpu, forwarding_cpus) {
			forwarding_cpus = append(forwarding_cpus, cpu)
		}
		if write {
			writeAffinityToFile(irq, uint64(cpu), topo.Ncpus)
		}
	}
	return forwarding_cpus
}

func AffinitizeIntf(intf string, strategy int) {
	switch strategy {
	case SEQ_NODES:
		affinitizeSeqNodes(intf, true)
		break
	case SAME_NODE:
		affinitizeSameNode(intf, true)
		break
	case ALL_NODES:
		affinitizeAllNodes(intf, true)
		break
	default:
		log.Println("unsupported strategy: ", strategy)
	}
}

func GetAffinitizeMapping(intf string, strategy int) []int {
	switch strategy {
	case SEQ_NODES:
		return affinitizeSeqNodes(intf, false)
		break
	case SAME_NODE:
		return affinitizeSameNode(intf, false)
		break
	case ALL_NODES:
		return affinitizeAllNodes(intf, false)
		break
	default:
		log.Fatal("unsupported strategy: ", strategy)
	}
	return []int{}
}
