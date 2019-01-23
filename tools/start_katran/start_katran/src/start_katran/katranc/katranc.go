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

package katranc

import (
	"log"
	"start_katran/lb_katran"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

func checkError(err error) {
	if err != nil {
		log.Fatal("Error: ", err)
	}
}

type KatranClient struct {
	client lb_katran.KatranServiceClient
}

func (kc *KatranClient) Init() {
	var opts []grpc.DialOption
	opts = append(opts, grpc.WithInsecure())
	conn, err := grpc.Dial("127.0.0.1:50051", opts...)
	if err != nil {
		log.Fatalf("Can't connect to local katran server! err is %v\n", err)
	}
	kc.client = lb_katran.NewKatranServiceClient(conn)
}

func (kc *KatranClient) ChangeMac(mac string) {
	newMac := lb_katran.Mac{Mac: mac}
	res, err := kc.client.ChangeMac(context.Background(), &newMac)
	checkError(err)
	if res.Success {
		log.Print("Mac address changed!")
	} else {
		log.Print("Mac was not changed")
	}
}

func (kc *KatranClient) GetMac() bool {
	mac, err := kc.client.GetMac(context.Background(), &lb_katran.Empty{})
	if err != nil {
		return false
	}
	log.Printf("Mac address is %v\n", mac.GetMac())
	return true
}
