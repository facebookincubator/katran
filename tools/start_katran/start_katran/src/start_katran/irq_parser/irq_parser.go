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

package irq_parser

import (
	"io/ioutil"
	"log"
	"regexp"
	"strconv"
	"strings"
)

const (
	PROC_IRQ_FILE      string = "/proc/interrupts"
	MSI_IRQ_DIR_PREFIX string = "/sys/class/net/"
	MSI_IRQ_DIR_SUFFIX string = "/device/msi_irqs/"
	kError             int    = -1
)

func parseInterruptLine(line string) int {
	line_slice := strings.Fields(line)
	if len(line_slice) < 1 {
		return kError
	}
	irq_num_slice := strings.Split(line_slice[0], ":")
	if len(irq_num_slice) < 1 {
		return kError
	}
	irq, err := strconv.Atoi(irq_num_slice[0])
	if err != nil {
		return kError
	}
	return irq
}

func parseProcIrqs(intf string) []int {
	var irqs []int
	regexp_string := ".*" + intf + ".*"
	intf_regexp, err := regexp.Compile(regexp_string)
	if err != nil {
		log.Fatal("cannot compile regexp for intf ", intf)
	}
	file_bytes, err := ioutil.ReadFile(PROC_IRQ_FILE)
	if err != nil {
		log.Fatal("cannot read /proc/interrupts file")
	}
	lines := strings.Split(string(file_bytes), "\n")
	for _, line := range lines {
		if len(intf) > 0 {
			if intf_regexp.MatchString(line) {
				irq := parseInterruptLine(line)
				if irq >= 0 {
					irqs = append(irqs, irq)
				}
			}
		} else {
			irq := parseInterruptLine(line)
			if irq >= 0 {
				irqs = append(irqs, irq)
			}
		}
	}
	return irqs
}

func getMsiIrqForDevice(intf string) []int {
	var msi_irqs []int
	msi_dir := MSI_IRQ_DIR_PREFIX + intf + MSI_IRQ_DIR_SUFFIX
	files, err := ioutil.ReadDir(msi_dir)
	if err != nil {
		log.Fatal("cannot read directory with msi irq numbers for ", intf, err)
	}
	for _, file := range files {
		irq, err := strconv.Atoi(file.Name())
		if err != nil {
			log.Fatal("cannot parse irq to int ", err)
		}
		msi_irqs = append(msi_irqs, irq)
	}
	return msi_irqs
}

func searchSlice(i int, s []int) bool {
	for _, v := range s {
		if v == i {
			return true
		}
	}
	return false
}

func parseMsiIrqs(intf string) []int {
	var irqs []int
	reg_irqs := parseProcIrqs("")
	msi_irqs := getMsiIrqForDevice(intf)
	for _, irq := range msi_irqs {
		if searchSlice(irq, reg_irqs) {
			irqs = append(irqs, irq)
		}
	}
	return irqs
}

func GetInterfaceIrq(intf string) []int {
	irqs := parseProcIrqs(intf)
	if len(irqs) != 0 {
		return irqs
	} else {
		return parseMsiIrqs(intf)
	}
}
