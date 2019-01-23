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

package start_binary

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os/exec"
	"start_katran/default_watcher"
	"start_katran/katranc"
	"strings"
	"time"
)

type StartKatranArgs struct {
	BinaryPath string
	Args       string
}

func readLog(log io.ReadCloser) {
	scanner := bufio.NewScanner(log)
	for scanner.Scan() {
		fmt.Println(scanner.Text())
	}

}

const (
	MAX_RETRIES int = 60
)

func StartKatran(kc *katranc.KatranClient, cmd StartKatranArgs) {
	default_mac := default_watcher.GetDefaultGatewayMac()
	if len(default_mac) == 0 {
		log.Fatal("cannot resolve mac address of default gateway")
	}
	cmd.Args = cmd.Args + " -default_mac=" + default_mac
	args := strings.Split(cmd.Args, " ")
	start_cmd := exec.Command(cmd.BinaryPath, args...)
	stdout, err := start_cmd.StdoutPipe()
	if err != nil {
		log.Fatal("error while trying to get stdout ", err)
	}
	stderr, err := start_cmd.StderrPipe()
	if err != nil {
		log.Fatal("error while trying to get stderr ", err)
	}
	if err := start_cmd.Start(); err != nil {
		log.Fatal("error while trying to start katran ", err)
	}
	go readLog(stdout)
	go readLog(stderr)
	kc.Init()
	cur_retry := 0
	for !kc.GetMac() {
		if cur_retry++; cur_retry == MAX_RETRIES {
			log.Fatal("Cannot connect to local katran server")
		}
		log.Printf("cannot reach katran server. retrying in one second\n")
		time.Sleep(1 * time.Second)
	}
	log.Printf("katran is up and running\n")
	go default_watcher.CheckDefaultGwMac(kc, default_mac)
	if err := start_cmd.Wait(); err != nil {
		log.Fatal("error while waiting katran to finish ", err)
	}
}
