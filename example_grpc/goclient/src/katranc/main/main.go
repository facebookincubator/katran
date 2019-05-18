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

package main

import (
	"flag"
	"fmt"
	"katranc/katranc"
)

const (
	IPPROTO_TCP = 6
	IPPROTO_UDP = 17
)

var (
	addService  = flag.Bool("A", false, "Add new virtual service")
	editService = flag.Bool("E", false, "Edit existing virtual service")
	delService  = flag.Bool("D", false, "Delete existing virtual service")
	addServer   = flag.Bool("a", false, "Add real server")
	editServer  = flag.Bool("e", false, "Edit real server")
	delServer   = flag.Bool("d", false, "Delete real server")
	tcpService  = flag.String("t", "",
		"Tcp service address. must be in format: <addr>:<port>")
	udpService = flag.String("u", "",
		"Udp service addr. must be in format: <addr>:<port>")
	realServer    = flag.String("r", "", "Address of the real server")
	realWeight    = flag.Int64("w", 1, "Weight (capacity) of real server")
	showStats     = flag.Bool("s", false, "Show stats/counters")
	showSumStats  = flag.Bool("sum", false, "Show summary stats")
	showLruStats  = flag.Bool("lru", false, "Show LRU related stats")
	showIcmpStats = flag.Bool("icmp", false, "Show ICMP 'packet too big' related stats")
	listServices  = flag.Bool("l", false, "List configured services")
	changeFlags   = flag.String("f", "",
		"change flags. Possible values: NO_SPORT, NO_LRU, QUIC_VIP, DPORT_HASH")
	unsetFlags = flag.Bool("unset", false, "Unset specified flags")
	newHc      = flag.String("new_hc", "", "Address of new backend to healtcheck")
	somark     = flag.Uint64("somark", 0, "Socket mark to specified backend")
	delHc      = flag.Bool("del_hc", false, "Delete backend w/ specified somark")
	listHc     = flag.Bool("list_hc", false, "List configured healthchecks")
	listMac    = flag.Bool("list_mac", false,
		"List configured mac address of default router")
	changeMac = flag.String("change_mac", "",
		"Change configured mac address of default router")
	clearAll    = flag.Bool("C", false, "Clear all configs")
	quicMapping = flag.String("quic_mapping", "",
		"mapping of real to connectionId. must be in <addr>=<id> format")
	listQuicMapping = flag.Bool("list_qm", false, "List current quic's mappings")
	delQuicMapping  = flag.Bool("del_qm", false,
		"Delete instead of adding specified quic mapping")
	katranServer  = flag.String("server", "127.0.0.1:50051",
		"Katran server listen address")
)

func main() {
	flag.Parse()
	var service string
	var proto int
	if *tcpService != "" {
		service = *tcpService
		proto = IPPROTO_TCP
	} else if *udpService != "" {
		service = *udpService
		proto = IPPROTO_UDP
	}
	var kc katranc.KatranClient
	kc.Init(*katranServer)
	if *changeMac != "" {
		kc.ChangeMac(*changeMac)
	} else if *listMac {
		kc.GetMac()
	} else if *addService {
		kc.AddOrModifyService(service, *changeFlags, proto, false, true)
	} else if *listServices {
		// TODO(tehnerd): print only specified tcp/udp service
		kc.List("", 0)
	} else if *delService {
		kc.DelService(service, proto)
	} else if *editService {
		kc.AddOrModifyService(service, *changeFlags, proto, true, !*unsetFlags)
	} else if *addServer || *editServer {
		kc.UpdateServerForVip(service, proto, *realServer, *realWeight, false)
	} else if *delServer {
		kc.UpdateServerForVip(service, proto, *realServer, *realWeight, true)
	} else if *delQuicMapping {
		kc.ModifyQuicMappings(*quicMapping, true)
	} else if *quicMapping != "" {
		kc.ModifyQuicMappings(*quicMapping, false)
	} else if *listQuicMapping {
		kc.ListQm()
	} else if *clearAll {
		kc.ClearAll()
	} else if *newHc != "" {
		kc.AddHc(*newHc, *somark)
	} else if *delHc {
		kc.DelHc(*somark)
	} else if *listHc {
		kc.ListHc()
	} else if *showStats {
		if *showSumStats {
			kc.ShowSumStats()
		} else if *showLruStats {
			kc.ShowLruStats()
		} else if *showIcmpStats {
			kc.ShowIcmpStats()
		} else {
			kc.ShowPerVipStats()
		}
	}
	fmt.Printf("exiting\n")
}
