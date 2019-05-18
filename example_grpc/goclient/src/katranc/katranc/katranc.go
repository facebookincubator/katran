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

package katranc

import (
	"fmt"
	"katranc/lb_katran"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

const (
	IPPROTO_TCP = 6
	IPPROTO_UDP = 17
	NO_SPORT    = 1
	NO_LRU      = 2
	QUIC_VIP    = 4
	DPORT_HASH  = 8
)

const (
	ADD_VIP = iota
	DEL_VIP
	MODIFY_VIP
)

var (
	flagTranslationTable = map[string]int64{
		"NO_SPORT":   NO_SPORT,
		"NO_LRU":     NO_LRU,
		"QUIC_VIP":   QUIC_VIP,
		"DPORT_HASH": DPORT_HASH,
	}
)

func checkError(err error) {
	if err != nil {
		log.Fatalf("Error: %v\n", err)
	}
}

type KatranClient struct {
	client lb_katran.KatranServiceClient
}

func (kc *KatranClient) Init(serverAddr string) {
	var opts []grpc.DialOption
	opts = append(opts, grpc.WithInsecure())
	conn, err := grpc.Dial(serverAddr, opts...)
	if err != nil {
		log.Fatalf("Can't connect to local katran server! err is %v\n", err)
	}
	kc.client = lb_katran.NewKatranServiceClient(conn)
}

func (kc *KatranClient) ChangeMac(mac string) {
	newMac := lb_katran.Mac{Mac: mac}
	res, err := kc.client.ChangeMac(context.Background(), &newMac)
	checkError(err)
	if res.Success == true {
		log.Print("Mac address changed!")
	} else {
		log.Print("Mac was not changed")
	}
}

func (kc *KatranClient) GetMac() {
	mac, err := kc.client.GetMac(context.Background(), &lb_katran.Empty{})
	checkError(err)
	log.Printf("Mac address is %v\n", mac.GetMac())
}

func parseToVip(addr string, proto int) lb_katran.Vip {
	var vip lb_katran.Vip
	vip.Protocol = int32(proto)
	if strings.Index(addr, "[") >= 0 {
		// v6 address. format [<addr>]:<port>
		v6re := regexp.MustCompile(`\[(.*?)\]:(.*)`)
		addr_port := v6re.FindStringSubmatch(addr)
		if addr_port == nil {
			log.Fatalf("invalid v6 address %v\n", addr)
		}
		vip.Address = addr_port[1]
		port, err := strconv.ParseInt(addr_port[2], 10, 32)
		vip.Port = int32(port)
		checkError(err)
	} else {
		// v4 address. format <addr>:<port>
		addr_port := strings.Split(addr, ":")
		if len(addr_port) != 2 {
			log.Fatalf("incorrect v4 address: %v\n", addr)
		}
		vip.Address = addr_port[0]
		port, err := strconv.ParseInt(addr_port[1], 10, 32)
		vip.Port = int32(port)
		checkError(err)
	}
	return vip
}

func parseToReal(addr string, weight int64) lb_katran.Real {
	var real lb_katran.Real
	real.Address = addr
	real.Weight = int32(weight)
	return real
}

func parseToQuicReal(mapping string) lb_katran.QuicReal {
	addr_id := strings.Split(mapping, "=")
	if len(addr_id) != 2 {
		panic("quic mapping must be in <addr>=<id> format")
	}
	id, err := strconv.ParseInt(addr_id[1], 10, 64)
	checkError(err)
	var qr lb_katran.QuicReal
	qr.Address = addr_id[0]
	qr.Id = int32(id)
	return qr
}

func (kc *KatranClient) AddOrModifyService(
	addr string, flagsString string, proto int, modify bool, setFlags bool) {
	log.Printf("Adding service: %v %v\n", addr, proto)
	vip := parseToVip(addr, proto)
	var flags int64
	var exists bool
	if flagsString != "" {
		if flags, exists = flagTranslationTable[flagsString]; !exists {
			log.Printf("unrecognized flag: %v\n", flagsString)
			return
		}
	}
	if modify {
		kc.UpdateService(vip, flags, MODIFY_VIP, setFlags)
	} else {
		kc.UpdateService(vip, flags, ADD_VIP, setFlags)
	}
}

func (kc *KatranClient) DelService(addr string, proto int) {
	log.Printf("Deleting service: %v %v\n", addr, proto)
	vip := parseToVip(addr, proto)
	kc.UpdateService(vip, 0, DEL_VIP, false)
}

func (kc *KatranClient) UpdateService(
	vip lb_katran.Vip, flags int64, action int, setFlags bool) {
	var vMeta lb_katran.VipMeta
	var ok *lb_katran.Bool
	var err error
	vMeta.Vip = &vip
	vMeta.Flags = flags
	vMeta.SetFlag = setFlags
	switch action {
	case MODIFY_VIP:
		ok, err = kc.client.ModifyVip(context.Background(), &vMeta)
		break
	case ADD_VIP:
		ok, err = kc.client.AddVip(context.Background(), &vMeta)
		break
	case DEL_VIP:
		ok, err = kc.client.DelVip(context.Background(), &vip)
		break
	default:
		break
	}
	checkError(err)
	if ok.Success {
		log.Printf("Vip modified\n")
	}
}

func (kc *KatranClient) UpdateServerForVip(
	vipAddr string, proto int, realAddr string, weight int64, delete bool) {
	vip := parseToVip(vipAddr, proto)
	real := parseToReal(realAddr, weight)
	var action lb_katran.Action
	if delete {
		action = lb_katran.Action_DEL
	} else {
		action = lb_katran.Action_ADD
	}
	var reals lb_katran.Reals
	reals.Reals = append(reals.Reals, &real)
	kc.ModifyRealsForVip(&vip, &reals, action)
}

func (kc *KatranClient) ModifyRealsForVip(
	vip *lb_katran.Vip, reals *lb_katran.Reals, action lb_katran.Action) {
	var mReals lb_katran.ModifiedRealsForVip
	mReals.Vip = vip
	mReals.Real = reals
	mReals.Action = action
	ok, err := kc.client.ModifyRealsForVip(context.Background(), &mReals)
	checkError(err)
	if ok.Success {
		log.Printf("Reals modified\n")
	}
}

func (kc *KatranClient) ModifyQuicMappings(mapping string, delete bool) {
	var action lb_katran.Action
	if delete {
		action = lb_katran.Action_DEL
	} else {
		action = lb_katran.Action_ADD
	}
	qr := parseToQuicReal(mapping)
	var qrs lb_katran.QuicReals
	qrs.Qreals = append(qrs.Qreals, &qr)
	var mqr lb_katran.ModifiedQuicReals
	mqr.Reals = &qrs
	mqr.Action = action
	ok, err := kc.client.ModifyQuicRealsMapping(
		context.Background(), &mqr)
	checkError(err)
	if ok.Success {
		log.Printf("Quic mapping modified\n")
	}
}

func (kc *KatranClient) GetAllVips() lb_katran.Vips {
	vips, err := kc.client.GetAllVips(context.Background(), &lb_katran.Empty{})
	checkError(err)
	return *vips
}

func (kc *KatranClient) GetAllHcs() lb_katran.HcMap {
	hcs, err := kc.client.GetHealthcheckersDst(
		context.Background(), &lb_katran.Empty{})
	checkError(err)
	return *hcs
}

func (kc *KatranClient) GetRealsForVip(vip *lb_katran.Vip) lb_katran.Reals {
	reals, err := kc.client.GetRealsForVip(context.Background(), vip)
	checkError(err)
	return *reals
}

func (kc *KatranClient) GetFlags(vip *lb_katran.Vip) uint64 {
	flags, err := kc.client.GetVipFlags(context.Background(), vip)
	checkError(err)
	return flags.Flags
}

func parseFlags(flags uint64) string {
	flags_str := ""
	if flags&uint64(NO_SPORT) > 0 {
		flags_str += " NO_SPORT "
	}
	if flags&uint64(NO_LRU) > 0 {
		flags_str += " NO_LRU "
	}
	if flags&uint64(QUIC_VIP) > 0 {
		flags_str += " QUIC_VIP "
	}
	if flags&uint64(DPORT_HASH) > 0 {
		flags_str += " DPORT_HASH "
	}
	return flags_str
}

func (kc *KatranClient) ListVipAndReals(vip *lb_katran.Vip) {
	reals := kc.GetRealsForVip(vip)
	proto := ""
	if vip.Protocol == IPPROTO_TCP {
		proto = "tcp"
	} else {
		proto = "udp"
	}
	fmt.Printf("VIP: %20v Port: %6v Protocol: %v\n",
		vip.Address,
		vip.Port,
		proto)
	flags := kc.GetFlags(vip)
	fmt.Printf("Vip's flags: %v\n", parseFlags(flags))
	for _, real := range reals.Reals {
		fmt.Printf("%-20v weight: %v\n",
			" ->"+real.Address,
			real.Weight)
	}
}

func (kc *KatranClient) List(addr string, proto int) {
	vips := kc.GetAllVips()
	log.Printf("vips len %v", len(vips.Vips))
	for _, vip := range vips.Vips {
		kc.ListVipAndReals(vip)
	}
}

func (kc *KatranClient) ClearAll() {
	fmt.Println("Deleting Vips")
	vips := kc.GetAllVips()
	for _, vip := range vips.Vips {
		ok, err := kc.client.DelVip(context.Background(), vip)
		if err != nil || !ok.Success {
			fmt.Printf("error while deleting vip: %v", vip.Address)
		}
	}
	fmt.Println("Deleting Healthchecks")
	hcs := kc.GetAllHcs()
	var Somark lb_katran.Somark
	for somark, _ := range hcs.Healthchecks {
		Somark.Somark = uint32(somark)
		ok, err := kc.client.DelHealthcheckerDst(context.Background(), &Somark)
		if err != nil || !ok.Success {
			fmt.Printf("error while deleting hc w/ somark: %v", somark)
		}
	}
}

func (kc *KatranClient) ListQm() {
	fmt.Printf("printing address to quic's connection id mapping\n")
	qreals, err := kc.client.GetQuicRealsMapping(
		context.Background(), &lb_katran.Empty{})
	checkError(err)
	for _, qr := range qreals.Qreals {
		fmt.Printf("real: %20v = connection id: %6v\n",
			qr.Address,
			qr.Id)
	}
}

func (kc *KatranClient) AddHc(addr string, somark uint64) {
	var hc lb_katran.Healthcheck
	hc.Somark = uint32(somark)
	hc.Address = addr
	ok, err := kc.client.AddHealthcheckerDst(context.Background(), &hc)
	checkError(err)
	if !ok.Success {
		fmt.Printf("error while add hc w/ somark: %v and addr %v", somark, addr)
	}
}

func (kc *KatranClient) DelHc(somark uint64) {
	var sm lb_katran.Somark
	sm.Somark = uint32(somark)
	ok, err := kc.client.DelHealthcheckerDst(context.Background(), &sm)
	checkError(err)
	if !ok.Success {
		fmt.Printf("error while deleting hc w/ somark: %v", somark)
	}
}

func (kc *KatranClient) ListHc() {
	hcs := kc.GetAllHcs()
	for somark, addr := range hcs.Healthchecks {
		fmt.Printf("somark: %10v addr: %10v\n",
			somark,
			addr)
	}
}

func (kc *KatranClient) ShowSumStats() {
	oldPkts := uint64(0)
	oldBytes := uint64(0)
	vips := kc.GetAllVips()
	for true {
		pkts := uint64(0)
		bytes := uint64(0)
		for _, vip := range vips.Vips {
			stats, err := kc.client.GetStatsForVip(context.Background(), vip)
			if err != nil {
				continue
			}
			pkts += stats.V1
			bytes += stats.V2
		}
		diffPkts := pkts - oldPkts
		diffBytes := bytes - oldBytes
		fmt.Printf("summary: %v pkts/sec %v bytes/sec\n", diffPkts, diffBytes)
		oldPkts = pkts
		oldBytes = bytes
		time.Sleep(1 * time.Second)
	}
}

func (kc *KatranClient) ShowLruStats() {
	oldTotalPkts := uint64(0)
	oldMiss := uint64(0)
	oldTcpMiss := uint64(0)
	oldTcpNonSynMiss := uint64(0)
	oldFallbackLru := uint64(0)
	for true {
		lruMiss := float64(0)
		tcpMiss := float64(0)
		tcpNonSynMiss := float64(0)
		udpMiss := float64(0)
		lruHit := float64(0)
		stats, err := kc.client.GetLruStats(
			context.Background(), &lb_katran.Empty{})
		if err != nil {
			continue
		}
		missStats, err := kc.client.GetLruMissStats(
			context.Background(), &lb_katran.Empty{})
		if err != nil {
			continue
		}
		fallbackStats, err := kc.client.GetLruFallbackStats(
			context.Background(), &lb_katran.Empty{})
		if err != nil {
			continue
		}
		diffTotal := stats.V1 - oldTotalPkts
		diffMiss := stats.V2 - oldMiss
		diffTcpMiss := missStats.V1 - oldTcpMiss
		diffTcpNonSynMiss := missStats.V2 - oldTcpNonSynMiss
		diffFallbackLru := fallbackStats.V1 - oldFallbackLru
		if diffTotal != 0 {
			lruMiss = float64(diffMiss) / float64(diffTotal)
			tcpMiss = float64(diffTcpMiss) / float64(diffTotal)
			tcpNonSynMiss = float64(diffTcpNonSynMiss) / float64(diffTotal)
			udpMiss = 1 - (tcpMiss + tcpNonSynMiss)
			lruHit = 1 - lruMiss
		}
		fmt.Printf("summary: %d pkts/sec. lru hit: %.2f%% lru miss: %.2f%% ",
			diffTotal, lruHit*100, lruMiss*100)
		fmt.Printf("(tcp syn: %.2f%% tcp non-syn: %.2f%% udp: %.2f%%)", tcpMiss,
			tcpNonSynMiss, udpMiss)
		fmt.Printf(" fallback lru hit: %d pkts/sec\n", diffFallbackLru)
		oldTotalPkts = stats.V1
		oldMiss = stats.V2
		oldTcpMiss = missStats.V1
		oldTcpNonSynMiss = missStats.V2
		oldFallbackLru = fallbackStats.V1
		time.Sleep(1 * time.Second)
	}
}

func (kc *KatranClient) ShowPerVipStats() {
	vips := kc.GetAllVips()
	statsMap := make(map[string]uint64)
	for _, vip := range vips.Vips {
		key := strings.Join([]string{
			vip.Address, strconv.Itoa(int(vip.Port)),
			strconv.Itoa(int(vip.Protocol))}, ":")
		statsMap[key+":pkts"] = 0
		statsMap[key+":bytes"] = 0
	}
	for true {
		for _, vip := range vips.Vips {
			key := strings.Join([]string{
				vip.Address, strconv.Itoa(int(vip.Port)),
				strconv.Itoa(int(vip.Protocol))}, ":")
			stats, err := kc.client.GetStatsForVip(context.Background(), vip)
			if err != nil {
				continue
			}
			diffPkts := stats.V1 - statsMap[key+":pkts"]
			diffBytes := stats.V2 - statsMap[key+":bytes"]
			fmt.Printf("vip: %16s : %8d pkts/sec %8d bytes/sec\n",
				key, diffPkts, diffBytes)
			statsMap[key+":pkts"] = stats.V1
			statsMap[key+":bytes"] = stats.V2
		}
		time.Sleep(1 * time.Second)
	}
}

func (kc *KatranClient) ShowIcmpStats() {
	oldIcmpV4 := uint64(0)
	oldIcmpV6 := uint64(0)
	for true {
		icmps, err := kc.client.GetIcmpTooBigStats(
			context.Background(), &lb_katran.Empty{})
		checkError(err)
		diffIcmpV4 := icmps.V1 - oldIcmpV4
		diffIcmpV6 := icmps.V2 - oldIcmpV6
		fmt.Printf(
			"ICMP \"packet too big\": v4 %v pkts/sec v6: %v pkts/sec\n",
			diffIcmpV4, diffIcmpV6)
		oldIcmpV4 = icmps.V1
		oldIcmpV6 = icmps.V2
		time.Sleep(1 * time.Second)
	}
}
