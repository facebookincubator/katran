# Copyright (C) 2018-present, Facebook, Inc.
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


import argparse
import time
from multiprocessing import Process, Queue

# pyre-fixme[21]: Could not find name `ARP` in `scapy.all`.
# pyre-fixme[21]: Could not find name `Ether` in `scapy.all`.
# pyre-fixme[21]: Could not find name `ICMP` in `scapy.all`.
# pyre-fixme[21]: Could not find name `ICMPv6EchoRequest` in `scapy.all`.
# pyre-fixme[21]: Could not find name `ICMPv6PacketTooBig` in `scapy.all`.
# pyre-fixme[21]: Could not find name `IP` in `scapy.all`.
# pyre-fixme[21]: Could not find name `IPv6` in `scapy.all`.
# pyre-fixme[21]: Could not find name `TCP` in `scapy.all`.
# pyre-fixme[21]: Could not find name `UDP` in `scapy.all`.
from scapy.all import (
    ARP,
    Ether,
    ICMP,
    ICMPv6EchoRequest,
    ICMPv6PacketTooBig,
    IP,
    IPv6,
    sendp,
    sniff,
    TCP,
    UDP,
)

QUEUE_READ_TIMEOUT = 5
RECVED_PCKTS = 0
MISSED_PCKTS = 1
INDEX_LEN = 2

TEST_PCKTS = [
    # pkt 1; reply expected
    # pyre-fixme[16]: Module `all` has no attribute `Ether`.
    Ether(src="0x002", dst="0x2")
    # pyre-fixme[16]: Module `all` has no attribute `IP`.
    / IP(src="192.168.1.1", dst="10.200.1.1")
    # pyre-fixme[16]: Module `all` has no attribute `UDP`.
    / UDP(sport=31337, dport=80)
    / "katran test pckt 01",
    # pkt 2; reply expected
    # pyre-fixme[16]: Module `all` has no attribute `Ether`.
    Ether(src="0x002", dst="0x2")
    # pyre-fixme[16]: Module `all` has no attribute `IP`.
    / IP(src="192.168.1.1", dst="10.200.1.1")
    # pyre-fixme[16]: Module `all` has no attribute `TCP`.
    / TCP(sport=31337, dport=80, flags="A")
    / "katran test pckt 02",
    # pkt 3; reply expected
    # pyre-fixme[16]: Module `all` has no attribute `Ether`.
    Ether(src="0x002", dst="0x2")
    # pyre-fixme[16]: Module `all` has no attribute `IP`.
    / IP(src="192.168.1.1", dst="10.200.1.2")
    # pyre-fixme[16]: Module `all` has no attribute `TCP`.
    / TCP(sport=31337, dport=42, flags="A")
    / "katran test pckt 03",
    # pkt 4; reply expected
    # pyre-fixme[16]: Module `all` has no attribute `Ether`.
    Ether(src="0x002", dst="0x2")
    # pyre-fixme[16]: Module `all` has no attribute `IP`.
    / IP(src="192.168.1.1", dst="10.200.1.3")
    # pyre-fixme[16]: Module `all` has no attribute `TCP`.
    / TCP(sport=31337, dport=80, flags="A")
    / "katran test pckt 04",
    # pkt 5; reply expected
    # pyre-fixme[16]: Module `all` has no attribute `Ether`.
    Ether(src="0x002", dst="0x2")
    # pyre-fixme[16]: Module `all` has no attribute `IPv6`.
    / IPv6(src="fc00:2::1", dst="fc00:1::1")
    # pyre-fixme[16]: Module `all` has no attribute `TCP`.
    / TCP(sport=31337, dport=80, flags="A")
    / "katran test pckt 05",
    # pkt 6; reply expected
    # pyre-fixme[16]: Module `all` has no attribute `Ether`.
    Ether(src="0x002", dst="0x2")
    # pyre-fixme[16]: Module `all` has no attribute `IP`.
    / IP(src="192.168.1.1", dst="10.200.1.3")
    # pyre-fixme[16]: Module `all` has no attribute `ICMP`.
    / ICMP(type="echo-request")
    / "katran test pckt 06",
    # pkt 7; reply expected
    # pyre-fixme[16]: Module `all` has no attribute `Ether`.
    Ether(src="0x002", dst="0x2")
    # pyre-fixme[16]: Module `all` has no attribute `IPv6`.
    / IPv6(src="fc00:2::1", dst="fc00:1::1")
    # pyre-fixme[16]: Module `all` has no attribute `ICMPv6EchoRequest`.
    / ICMPv6EchoRequest()
    / "katran test pckt 07",
    # pkt 8; reply expected
    # pyre-fixme[16]: Module `all` has no attribute `Ether`.
    Ether(src="0x002", dst="0x2")
    # pyre-fixme[16]: Module `all` has no attribute `IP`.
    / IP(src="192.168.100.1", dst="10.200.1.1")
    # pyre-fixme[16]: Module `all` has no attribute `ICMP`.
    / ICMP(type="dest-unreach", code="fragmentation-needed")
    # pyre-fixme[16]: Module `all` has no attribute `IP`.
    / IP(src="10.200.1.1", dst="192.168.1.1")
    # pyre-fixme[16]: Module `all` has no attribute `TCP`.
    / TCP(sport=80, dport=31337)
    / "katran test pckt 08",
    # pkt 9; reply expected
    # pyre-fixme[16]: Module `all` has no attribute `Ether`.
    Ether(src="0x002", dst="0x2")
    # pyre-fixme[16]: Module `all` has no attribute `IPv6`.
    / IPv6(src="fc00:200::1", dst="fc00:1::1")
    # pyre-fixme[16]: Module `all` has no attribute `ICMPv6PacketTooBig`.
    / ICMPv6PacketTooBig()
    # pyre-fixme[16]: Module `all` has no attribute `IPv6`.
    / IPv6(src="fc00:1::1", dst="fc00:2::1")
    # pyre-fixme[16]: Module `all` has no attribute `TCP`.
    / TCP(sport=80, dport=31337)
    / "katran test pckt 09",
    # pkt 10; will be droped on katran side
    # pyre-fixme[16]: Module `all` has no attribute `Ether`.
    Ether(src="0x002", dst="0x2")
    # pyre-fixme[16]: Module `all` has no attribute `IP`.
    / IP(src="192.168.1.1", dst="10.200.1.1", ihl=6)
    # pyre-fixme[16]: Module `all` has no attribute `TCP`.
    / TCP(sport=31337, dport=80, flags="A")
    / "katran test pckt 10",
    # pkt 11; will be droped on katran side
    # pyre-fixme[16]: Module `all` has no attribute `Ether`.
    Ether(src="0x002", dst="0x2")
    # pyre-fixme[16]: Module `all` has no attribute `IP`.
    / IP(src="192.168.1.1", dst="10.200.1.1", ihl=5, flags="MF")
    # pyre-fixme[16]: Module `all` has no attribute `TCP`.
    / TCP(sport=31337, dport=80, flags="A")
    / "katran test pckt 11",
    # pkt 12; will be droped on katran side
    # pyre-fixme[16]: Module `all` has no attribute `Ether`.
    Ether(src="0x002", dst="0x2")
    # pyre-fixme[16]: Module `all` has no attribute `IPv6`.
    / IPv6(src="fc00:2::1", dst="fc00:1::1", nh=44)
    # pyre-fixme[16]: Module `all` has no attribute `TCP`.
    / TCP(sport=31337, dport=80, flags="A")
    / "katran test pckt 12",
    # pkt 13; will be passed to katran's tcp stack; no reply expected
    # pyre-fixme[16]: Module `all` has no attribute `Ether`.
    Ether(src="0x002", dst="0x2")
    # pyre-fixme[16]: Module `all` has no attribute `IP`.
    / IP(src="192.168.1.1", dst="10.200.1.1", ihl=5)
    # pyre-fixme[16]: Module `all` has no attribute `TCP`.
    / TCP(sport=31337, dport=82, flags="A")
    / "katran test pckt 13",
    # pkt 14; will be passed to katran's tcp stack; no reply expected
    # pyre-fixme[16]: Module `all` has no attribute `Ether`.
    Ether(src="0x002", dst="0x2")
    # pyre-fixme[16]: Module `all` has no attribute `IPv6`.
    / IPv6(src="fc00:2::1", dst="fc00:1::1")
    # pyre-fixme[16]: Module `all` has no attribute `TCP`.
    / TCP(sport=31337, dport=82, flags="A")
    / "katran test pckt 14",
    # pkt 15; will be passed to katran's tcp stack; no reply expected
    # pyre-fixme[16]: Module `all` has no attribute `Ether`.
    # pyre-fixme[16]: Module `all` has no attribute `ARP`.
    Ether(src="0x002", dst="0x2") / ARP(),
]

# we are expecting replies for first 9 packets from TEST_PCKTS
# keys in this dict are numbers after "katran test pckt" in rcved pckt
EXPECTED_REPLY = {
    1: "packet to UDP based v4 VIP (and v4 real)",
    2: "packet to TCP based v4 VIP (and v4 real)",
    3: "packet to TCP based v4 VIP (and v4 real; any dst ports)",
    4: "packet to TCP based v4 VIP (and v6 real)",
    5: "packet to TCP based v6 VIP (and v6 real)",
    6: "v4 ICMP echo-request",
    7: "v6 ICMP echo-request",
    8: "v4 ICMP dest-unreachabe fragmentation-needed",
    9: "v6 ICMP packet-too-big",
}


def parse_args():
    parser = argparse.ArgumentParser(
        usage="""
        This is a tool for forwarding plane (NIC driver's support for XDP) tests
        Topology:
        <pktgen> --- <l2 network> --- <katran host>
        Usage:
        1) copy this file to pktgen host.
        2) on katran host run:
         ./katranadm.par -Au 10.200.1.1:80
         ./katranadm.par -au 10.200.1.1:80 -r 10.0.0.1
         ./katranadm.par -au 10.200.1.1:80 -r 10.0.0.2
         ./katranadm.par -au 10.200.1.1:80 -r 10.0.0.3
         ./katranadm.par -At 10.200.1.1:80
         ./katranadm.par -at 10.200.1.1:80 -r 10.0.0.1
         ./katranadm.par -at 10.200.1.1:80 -r 10.0.0.2
         ./katranadm.par -at 10.200.1.1:80 -r 10.0.0.3
         ./katranadm.par -At 10.200.1.2:0
         ./katranadm.par -at 10.200.1.2:0  -r 10.0.0.1
         ./katranadm.par -at 10.200.1.2:0  -r 10.0.0.2
         ./katranadm.par -at 10.200.1.2:0  -r 10.0.0.3
         ./katranadm.par -At 10.200.1.3:80
         ./katranadm.par -at 10.200.1.3:80   -r fc00::1
         ./katranadm.par -at 10.200.1.3:80   -r fc00::2
         ./katranadm.par -at 10.200.1.3:80   -r fc00::3
         ./katranadm.par -At [fc00:1::1]:80
         ./katranadm.par -at [fc00:1::1]:80  -r fc00::1
         ./katranadm.par -at [fc00:1::1]:80  -r fc00::2
         ./katranadm.par -at [fc00:1::1]:80  -r fc00::3
         ./katranadm.par --change_mac <mac of the pktgen host>
        3) on pktgen host:
           3.1) run tcpdump -evni eth0 ether host  <mac of katran>
           3.2) run ./fplane-testing.par --katran-mac "<mac of katran>"
           3.3) check that tcpdump output is sane
        """
    )
    parser.add_argument(
        "--katran-mac", type=str, help="Mac address of Katran load balancer"
    )
    parser.add_argument(
        "--iface", type=str, default="eth0", help="interface to send packets from"
    )
    parser.add_argument(
        "--verbose", action="store_true", help="print verbose info about recved pckts"
    )
    args = parser.parse_args()
    return args


class FplaneTester:
    def __init__(self, args, queue):
        self._verbose = args.verbose
        self._katran_mac = args.katran_mac
        self._iface = args.iface
        self._missed_pckts = EXPECTED_REPLY
        self._recved_pckts = {}
        self._queue = queue

    def sniff_packets(self):
        pcap_filter = f"ether src host {self._katran_mac}"
        sniff(filter=pcap_filter, iface=self._iface, prn=self.process_received_packet)

    def send_test_pckts(self):
        for pckt in TEST_PCKTS:
            pckt.dst = self._katran_mac
            sendp(pckt, iface=self._iface)

    def check_pckt(self, pckt):
        marker_line = b"katran test pckt "
        init_index = pckt.find(marker_line)
        if init_index < 0:
            return
        index_start = init_index + len(marker_line)
        index_end = index_start + INDEX_LEN
        test_num = pckt[index_start:index_end]
        try:
            test_num = int(test_num)
        except ValueError:
            # we cant convert index to int. probably some bogus packet
            return
        if test_num in self._missed_pckts:
            self._recved_pckts[test_num] = self._missed_pckts[test_num]
            del self._missed_pckts[test_num]
            self._queue.put((self._recved_pckts, self._missed_pckts))

    def read_queue(self):
        msg = self._queue.get(timeout=QUEUE_READ_TIMEOUT)
        self._recved_pckts = msg[RECVED_PCKTS]
        self._missed_pckts = msg[MISSED_PCKTS]

    def print_test_results(self):
        for test in self._recved_pckts.values():
            print(f"test: {test:70} passed")
        for test in self._missed_pckts.values():
            print(f"test: {test:70} failed")

    def process_received_packet(self, packet):
        if self._verbose:
            print(packet.show())
        self.check_pckt(bytes(packet))


def main():
    q = Queue()
    args = parse_args()
    tester = FplaneTester(args, q)
    p = Process(target=tester.sniff_packets)
    p.start()
    print("in output make sure that packets from 1 to 9 are recved!")
    time.sleep(5)
    print("starting tests")
    tester.send_test_pckts()
    while True:
        try:
            tester.read_queue()
        except Exception:
            p.terminate()
            # read from queue timed out
            break
    print("tests complited")
    tester.print_test_results()


if __name__ == "__main__":
    main()
