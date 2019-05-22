# Examples

### Example of katran library usage -

In this repository we provide two simple examples ([example](example) and [example_grpc](example_grpc) dirs)
on how katran library can be used in production. They are based on thrift and 
gRPC RPC frameworks. The actual code of this wrappers is simple, they just 
perform one-to-one translation between exposed RPC endpoint to internal methods of katran library.

### Example scenario:

We are going to use VM to illustrate simple steps of how katran can be used.
we will show:

1. How katran can be used in standalone mode.
2. How katran can be used in shared mode (we are also provide an example of
root xdp program).
3. How katran's healthchecking forwarding plane could be used
4. We are going to configure one VIP with one real and show tcpdump's output
to show how packets look on the wire.

### Starting katran
As a first step make sure that BPF's jit is enabled (for best possible performance):
net.core.bpf_jit_enable sysctl should be set to 1:
```
sysctl net.core.bpf_jit_enable=1
```

We are going to use gRPC in our example (but all this steps
are applicable to thrift as well. They are intentionally written 
to look and feel alike (with same flags, same behavior etc). The only
difference is where the actual binaries are located).

First of all, we need to build cli tool, which will allow us to
communicate with the server. You must have ‘go toolchain’ installed,
as well as all the required libraries to be able to build gRPC client(https://grpc.io/docs/tutorials/basic/go.html).
To build the cli tool, you need to run a script from `example_grpc` dir:

```
./build_grpc_client.sh
```

Before starting katran you need to collect this data (here we are describing manual steps. However, it's highly
recommended that for production deployments you collect this data with some form of prerun scripts):

1. __MAC address of default gateway__ : katran offloads all the routing to default gateway. It's doing so
by sending everything, which we determined as a traffic toward configured VIP, to it.
you can get this info w/ a help of this commands:

```
$ ip route  | grep default
default via 10.0.2.2 dev enp0s3 proto dhcp src 10.0.2.15 metric 100
$ ip n show | grep 10.0.2.2
10.0.2.2 dev enp0s3 lladdr 52:54:00:12:35:02 REACHABLE
```

In this example mac address of default router is `52:54:00:12:35:02`

2. __You need to know how many receive queues your NIC has and what the mapping between them and cpus__ :
katran has built in optimizations, so it would allocate memory only for CPUs 
which are actually forwarding traffic. If you do not need this 
optimization - you can omit this step, by specifying that all CPUs are using for forwarding
(for example: on 4 CPU server just specify -forwarding_cores="0,1,2,3" flag)

If you want to use memory optimization here is an example that illustrates how to achieve this:
You need to be familiar with [RSS](https://github.com/torvalds/linux/blob/master/Documentation/networking/scaling.txt)
and how [IRQ affinity ("pinning")](https://github.com/torvalds/linux/blob/master/Documentation/IRQ-affinity.txt) works.

To get a list of how many rx queues are currently configured for your interface you can run this command:

```
ethtool -l <interface name>
```

Let’s imagine that you have a server with 4 CPUs but only one RX queue for you NIC.
Next step is to get an IRQ number which has been used by your NIC, to do this you can inspect `/proc/interrupts`
(in this example enp0s3 is an interface)

```
$ cat /proc/interrupts  | grep enp0s3
 19:     740509   IO-APIC  19-fasteoi   enp0s3
```

The first field is an IRQ number. In this example `enp0s3` is using IRQ 19. If you have a NIC with multiple rx queues, you will
see multiple lines in this output.

Next step is to "pin" this IRQ to specific CPU (if your NIC has multiple queues (e.g. N)/ you would see multiple IRQs from the previous command -
you will need to repeat this step N times. For the best performance you need to make 1 to 1 mapping between CPU and IRQ, and they should not overlap
(e.g. a single CPU should not be assigned to multiple IRQs)). If you are running irqbalance (default on ubuntu/systemd) - it's recommended to turn it off

```
$ sudo systemctl stop irqbalance
$ sudo systemctl disable irqbalance
```

```sh
$ cd /proc/irq/19  # 19 is an IRQ number from previous step
$ sudo  sh -c "echo 1 > smp_affinity"  # allow only cpu 0 (smp_affinity is a bitmask) to handle IRQ 19
```

3. If you use a server with multiple physical CPUs (hence multiple NUMA domains) you need to collect
CPU to NUMA node mapping (if you want to use NUMA hints for memory allocation,
to achieve maximum performance. if you dont need this optimization - just omit
-numa_nodes cli flag)
e.g. for cpu0 this info (NUMA id) is located here:

```
$ cat /sys/devices/system/cpu/cpu0/topology/physical_package_id
```

After collecting this mappings between cpus and NUMA nodes, for each cpu in -forwarding_cores list on the same 
position in -numa_nodes would be ID of NUMA for this cpu.

For example: We have a server with 4 forwarding cpu 0,1,2,3. cpus 0 and 2 belongs to NUMA node 0
cpus 1 and 3 - to NUMA node 1. for this scenario cli flags would looks like this:
-forwarding_cores="0,1,2,3" -numa_nodes="0,1,0,1"

You need to create tunneling interfaces (katran uses ipip encapsulation for both forwarding and for the healthchecks).
On the load balancer side, this tunnels is going to be used for healthchecks forwarding (and if you don't need to run healthchecks from it
this step could be omitted (by passing -hc_forwarding=false). This could be desirable if you are using dedicated servers for healthchecking
and loadbalancer get the state of the world from them (in this case no need to run local healthchecks))

Same interfaces must be configured on the real side, so it would be able to receive ipip packets and decapsulate them.

```
$ sudo ip link add name ipip0 type ipip external
$ sudo ip link add name ipip60 type ip6tnl external
$ sudo ip link set up dev ipip0
$ sudo ip link set up dev ipip60
```

If you need to run bpf program for healthchecks forwarding - you need to
attach clsact qdisc on egress interface (enp0s3 in this example):

```
$ sudo tc qd add  dev enp0s3 clsact
```

After all this preparations we are ready to start katran_server

#### Starting katran in standalone mode

standalone mode is when katran is attached to the interface directly (and you wont
be able to run any other XDP program on this interface)

```
$ sudo ./build/example_grpc/katran_server_grpc -balancer_prog ./deps/bpfprog/bpf/balancer_kern.o -default_mac 52:54:00:12:35:02 -forwarding_cores=0 -healthchecker_prog ./deps/bpfprog/bpf/healthchecking_ipip.o -intf=enp0s3 -ipip_intf=ipip0 -ipip6_intf=ipip60 -lru_size=10000
```

In this example:
1. MAC address of default router is 52:54:00:12:35:02
2. Only cpu 0 is configured for forwarding (by IRQ affinity).
3. We want to run healthchecking bpf program.
4. We are using enp0s3 interface for load balancing (packets would be received on this interface).
5. ipip0 and ipip60 interfaces has been created prior for healthchecks forwarding.
6. The size of connection table (number of flows which we are going to track) has been configured to 10000 (default is 8mil).

#### starting katran is shared mode
This is a recommended way to run anything XDP related. This method allows you to run multiple XDP programs
by doing a simple trick: install special "root" xdp program that runs programs from the prog_array
(the only requirement is that programs need to be aware about each other, e.g. first program in a chain in the end of the
run must try to run other programs in prog_array). This allows us to run XDP based firewall in front
of your load balancer.
In this repository we provide a simple example of such "root" xdp program.
We configure a small prog_array and try to run xdp programs from there.
It is located in `katran/lib/bpf/xdp_root.c`

For our example we are going to use ./install_xdproot.sh script from the repository.
This script assumes that "root" program will be attached to enp0s3 interface
and it will automatically attach bpffs (BPF file system)
and attach shared prog_array (array where other XDP programs would register themselves)

```
./install_xdproot.sh
```

You will see that bpffs has been mounted and special file has been created on this
filesystem:

```
$ mount | grep bpf
bpffs on /sys/fs/bpf type bpf (rw,relatime)
$ ls -alh /sys/fs/bpf/jmp_eth0
-rw------- 1 root root 0 Mar 18 18:01 /sys/fs/bpf/jmp_eth0
```

Now you need to run katran binary with special flags so it will know that it should
work in "shared" mode. The flags are:

1. `-map_path` - this is a path to file, created by "root" xdp program

2. `-prog_pos` - this is a position in prog_array (in our example
The size of prog array is 3 elements (defined in "root" xdp program)
and we want our load balancer to be registered as the last program in this
array (hence the usage of index 2). This allows us to run 2 xdp programs,
if needed, in front of load balancer.


```
$ sudo ./build/example_grpc/katran_server_grpc -balancer_prog ./deps/bpfprog/bpf/balancer_kern.o -default_mac 52:54:00:12:35:02 -forwarding_cores=0 -healthchecker_prog ./deps/bpfprog/bpf/healthchecking_ipip.o -intf=enp0s3 -ipip_intf=ipip0 -ipip6_intf=ipip60 -lru_size=10000 -map_path /sys/fs/bpf/jmp_eth0 -prog_pos=2
```

### Configuring healthchecks forwarding

This is applicable only if you want to run healthchecks from the load balancer itself
(e.g. you have started it with -hc_forwarding=true (default))

healthchecks forwarding works in a way such that you configure socket mark to real server mappings.
Then if you want to check the health of a vip on a specific real - you send a packet w/ configured socket mark
In our example we will use a simple python program to generate such packets (just to show how socket mark could be configured
on a socket with setsockopt).

Let’s imagine that we have two VIPs: `10.100.1.1` and `fc00:100::1`

For v4 VIP we are using reals with addresses:
`10.200.200.1`, `10.200.200.2` and  `fc00:200::1`

For v6 VIP we are using only one real with address: `fc00:200::1`

To configure so_mark to real mapping, we are going to use go client that we built earlier:

```
$ cp  ./example_grpc/goclient/bin/main ./katran_goclient
$ ./katran_goclient -new_hc 10.200.200.1 -somark 1000
exiting
$ ./katran_goclient -new_hc 10.200.200.2 -somark 1001
exiting
$ ./katran_goclient -new_hc fc00:200::1 -somark 1002
exiting
```

To list all currently configured somark to real mapping you can run this command:

```
$ ./katran_goclient -list_hc
somark: 1000 addr: 10.200.200.1
somark: 1001 addr: 10.200.200.2
somark: 1002 addr: fc00:200::1
exiting
```

Now let’s open second screen and run tcpdump program there with filter "proto 4 or proto 41"
this filter will match all ipip or ip6ip6 packets.

lets use this simple python script to emulate a program which is doing healthchecks (hc_it_client.py)

```python
#!/usr/bin/env python
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
import socket
import sys
import time

SO_MARK = 36


def send_packet(fam, num, dst, fwmark):
    if fam == "4":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    else:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, SO_MARK, int(fwmark))
    for _i in range(0, int(num)):
        s.sendto("PING", (dst, 1337))
        time.sleep(1)


def main():
    send_packet(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])


if __name__ == "__main__":
    main()
```

In the first screen lets run our helper python program to generate udp packets toward `10.100.1.1` and `fc00:100::1` (our VIPs)

```
$ sudo python hc_it_client.py 4 4 10.100.1.1  1000  # 4 packets with dst 10.100.1.1 and socket mark 1000
$ sudo python hc_it_client.py 4 4 10.100.1.1  1001  # same but with socket mark 1001
$ sudo python hc_it_client.py 4 4 10.100.1.1  1002  # w/ socket mark 1002
```

As expected, in the tcpdump output we can see that depending on socket mark packets are sent as ipip encapsulated
toward specific reals

```
$ sudo tcpdump -ni enp0s3 proto 4 or proto 41
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on enp0s3, link-type EN10MB (Ethernet), capture size 262144 bytes
18:25:10.438333 IP 10.0.2.15 > 10.200.200.1: IP 10.0.2.15.55835 > 10.100.1.1.1337: UDP, length 4 (ipip-proto-4)
18:25:11.439472 IP 10.0.2.15 > 10.200.200.1: IP 10.0.2.15.55835 > 10.100.1.1.1337: UDP, length 4 (ipip-proto-4)
18:25:12.441076 IP 10.0.2.15 > 10.200.200.1: IP 10.0.2.15.55835 > 10.100.1.1.1337: UDP, length 4 (ipip-proto-4)
18:25:13.443512 IP 10.0.2.15 > 10.200.200.1: IP 10.0.2.15.55835 > 10.100.1.1.1337: UDP, length 4 (ipip-proto-4)
18:25:16.003227 IP 10.0.2.15 > 10.200.200.2: IP 10.0.2.15.59985 > 10.100.1.1.1337: UDP, length 4 (ipip-proto-4)
18:25:17.004897 IP 10.0.2.15 > 10.200.200.2: IP 10.0.2.15.59985 > 10.100.1.1.1337: UDP, length 4 (ipip-proto-4)
18:25:18.006895 IP 10.0.2.15 > 10.200.200.2: IP 10.0.2.15.59985 > 10.100.1.1.1337: UDP, length 4 (ipip-proto-4)
18:25:19.008000 IP 10.0.2.15 > 10.200.200.2: IP 10.0.2.15.59985 > 10.100.1.1.1337: UDP, length 4 (ipip-proto-4)
18:25:21.043145 IP6 fc00:33::2 > fc00:200::1: IP 10.0.2.15.53918 > 10.100.1.1.1337: UDP, length 4
18:25:22.044215 IP6 fc00:33::2 > fc00:200::1: IP 10.0.2.15.53918 > 10.100.1.1.1337: UDP, length 4
18:25:23.045364 IP6 fc00:33::2 > fc00:200::1: IP 10.0.2.15.53918 > 10.100.1.1.1337: UDP, length 4
18:25:24.047293 IP6 fc00:33::2 > fc00:200::1: IP 10.0.2.15.53918 > 10.100.1.1.1337: UDP, length 4
```

for v6 vip

```
$ sudo python hc_it_client.py 6 4 fc00:100::1  1002
```

```
18:30:05.300691 IP6 fc00:33::2 > fc00:200::1: IP6 fc00:33::2.37751 > fc00:100::1.1337: UDP, length 4
18:30:06.302625 IP6 fc00:33::2 > fc00:200::1: IP6 fc00:33::2.37751 > fc00:100::1.1337: UDP, length 4
18:30:07.304750 IP6 fc00:33::2 > fc00:200::1: IP6 fc00:33::2.37751 > fc00:100::1.1337: UDP, length 4
18:30:08.306662 IP6 fc00:33::2 > fc00:200::1: IP6 fc00:33::2.37751 > fc00:100::1.1337: UDP, length 4
```

ipv6 in ipv4 encapsulation is not supported (for example you cannot have IPv6 VIP with IPv4 reals. However, you
can have IPv4 VIP with IPv6 reals)

###  Configuration of forwarding plane

We will use simple topology for this example:

```
<client> ---- <net> ---- <katran> ---- <net> ---- <server>
```

client will try to initiate a ssh session w/ a VIP (10.200.200.1)
and then run scp command to copy a file from there.

We will have this VIP configured on katran with 1 real ("server")

In our example we will see:

1. How packets forwarded from "client" to "server".
2. How katran configured for this to work.
3. How encapsulation looks like.
4. How "server" must be configured to work properly.
5. How replies are forward from "server" to "client" directly (katran works
in DSR (Direct Sever Return) mode).


Let’s start w/ configuration of the server:

1. We need to create ipip interfaces on the server (katran is using ipip as encapsulation
for packet forwarding).

```
$ sudo ip link add name ipip0 type ipip external
$ sudo ip link add name ipip60 type ip6tnl external
$ sudo ip link set up dev ipip0
$ sudo ip link set up dev ipip60
```

2. Specific to the linux is that for ipip interface to work - it must have
at least single ip configured. We are going to configure an ip from 127.0.0.0/8 network
as this is somehow artificial IP (it has local significance) - we could reuse the same
IP across the fleet -

```
$ sudo ip a a 127.0.0.42/32 dev ipip0
```

3. Since most of the time server is connected w/ a single interface - we don't need rp_filter
feature:

```
for sc in $(sysctl -a | awk '/\.rp_filter/ {print $1}'); do  echo $sc ; sudo sysctl ${sc}=0; done
```

4. VIP must be configured on the real

```
$ sudo ip a a 10.200.200.1/32 dev lo
```

After this 4 steps server is fully configured to receive traffic from the client.

Let’s look on the katran's configuration:

1. First of all you need to configure a VIP. In our case we are interested in traffic
Towards ip 10.200.200.1 and destination port 22/tcp (ssh). To interact with katran we are using
go based client, you can run it w/ `--help` flag to see what options it supports.

```
$ ./katran_goclient -A -t 10.200.200.1:22
2018/03/19 12:50:02 Adding service: 10.200.200.1:22 6
2018/03/19 12:50:02 Vip modified
exiting

```
in this example:
 - -A - Add a new service
 - -t - new service is tcp based
 - :22 - we are interested only for traffic w/ dst port 22

If this was IPv6 based VIP we would need to specify it inside square brackets. for example
`[fc00::1]:22`

2. we need to add a real to this VIP. In this case: ip address of the real would be 10.0.0.2. As in our example
VIP will have only single real - we will not configure any weight for this real.

```
$ ./katran_goclient -a -t 10.200.200.1:22 -r 10.0.0.2
2018/03/19 12:52:59 Reals modified
exiting
```

 - -a - add a new real to specified VIP
 - -r - ip address of the real


You can get a list of all VIPs and corresponding real w/ -l flag -

```
$ ./katran_goclient -l
2018/03/19 12:54:05 vips len 1
VIP: 10.200.200.1 Port: 22 Protocol: tcp
Vip's flags:
-> 10.0.0.2 weight 1
exiting
```

Now, let’s initiate a ssh session from the client and look at tcpdump from the server side and
stats output from katran. At katran, we are going to run client w/ `-s` and `-lru` flags. 
This flags will show total packet and byte rate. as well as will show connection table hit
percentage.

```
./katran_goclient -s -lru
summary: 0 pkts/sec. lru hit: 0.00% lru miss: 0.00% (tcp syn: 0.00% tcp non-syn: 0.00% udp: 0.00%) fallback lru hit: 0 pkts/sec
summary: 9 pkts/sec. lru hit: 88.89% lru miss: 11.11% (tcp syn: 0.11% tcp non-syn: 0.00% udp: 0.00%) fallback lru hit: 0 pkts/sec
summary: 0 pkts/sec. lru hit: 0.00% lru miss: 0.00% (tcp syn: 0.00% tcp non-syn: 0.00% udp: 0.00%) fallback lru hit: 0 pkts/sec
summary: 2 pkts/sec. lru hit: 100.00% lru miss: 0.00% (tcp syn: 0.00% tcp non-syn: 0.00% udp: 0.00%) fallback lru hit: 0 pkts/sec
```

On the server side, if we run tcpdump, we can see ingress ipip packets and egress regular IP, with a destination of the client -

```
$ sudo tcpdump -ni enp0s8 proto 4 or host 10.200.200.1
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on enp0s8, link-type EN10MB (Ethernet), capture size 262144 bytes
15:48:53.338329 IP 172.16.215.45 > 10.0.0.2: IP 10.0.0.3.11991 > 10.200.200.1.22: Flags [S], seq 3909606823, win 65535, options [mss 1460,nop,wscale 6,sackOK,TS val 10629589 ecr 0], length 0 (ipip-proto-4)
15:48:53.338438 IP 10.200.200.1.22 > 10.0.0.3.11991: Flags [S.], seq 2576041211, ack 3909606824, win 28960, options [mss 1460,sackOK,TS val 2916608748 ecr 10629589,nop,wscale 6], length 0
15:48:53.338864 IP 172.16.215.45 > 10.0.0.2: IP 10.0.0.3.11991 > 10.200.200.1.22: Flags [.], ack 1, win 4106, options [nop,nop,TS val 10629590 ecr 2916608748], length 0 (ipip-proto-4)
15:48:53.339649 IP 172.16.215.45 > 10.0.0.2: IP 10.0.0.3.11991 > 10.200.200.1.22: Flags [P.], seq 1:39, ack 1, win 4106, options [nop,nop,TS val 10629591 ecr 2916608748], length 38 (ipip-proto-4)
15:48:53.339687 IP 10.200.200.1.22 > 10.0.0.3.11991: Flags [.], ack 39, win 453, options [nop,nop,TS val 2916608749 ecr 10629591], length 0
15:48:53.350785 IP 10.200.200.1.22 > 10.0.0.3.11991: Flags [P.], seq 1:33, ack 39, win 453, options [nop,nop,TS val 2916608761 ecr 10629591], length 32
15:48:53.351821 IP 172.16.215.45 > 10.0.0.2: IP 10.0.0.3.11991 > 10.200.200.1.22: Flags [P.], seq 39:1375, ack 33, win 4106, options [nop,nop,TS val 10629603 ecr 2916608761], length 1336 (ipip-proto-4)

```

Interesting part here is the source of IPIP packets – that it is not equal to the source of the load balancer, but instead it's a crafted one,
where first two octets are equal to 172.16 (defined in `katran/lib/bpf/balancer_const.h` and is configurable)
in IPIP_*_PREFIX macros) and the last two are crafted in a way, that they would be the same for a single tcp flow
but different flows will have different source IP. This is designed  intentionally to leverage
RSS capability of the NIC.

So in a nutshell, packet flow looks like this:

1. From "client" to "katran" (which advertises VIP reachability to the network) it's IP packets
with a src of "client" and dst of the VIP.

2. When "katran" receives this packets, it encapsulates them and sends to the real. this packets
are going to be IPIP encapsulated. inner header would state the same ("client" -> "VIP").
The outer header contains specifically crafted src address and destination would be address of the
"server".

3. When server receives this IPIP packet - it removes outer ip header, and processes original packet
and while sending replies - it sends it directly from the "VIP" to the "client".

