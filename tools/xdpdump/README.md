# xdpdump
tcpdump like to which is working with XDP.

as XDP works before kernel's tcp/ip stack, regular debug and troubleshooting tools,
like tcpdump, doesn't work. this is seriously limits operational usubility.
fortunately there is a way to get the same features in XDP world.
xdpdump is implementing tcpdump like tool, which can helps to troubleshoot
forwarding related issues. it allow to capture packets, matched by specified
filter, and, optionally, save em in pcap format for further debugging.

# environment requirments.
xdpdump only works when katran is running in shared mode (w/ rootlet program).
xdpdump inserts itself on first position in rootlet's prog array and run
before any other xdp program.

### example of usage.
CLI flags:
```
    -bpf_mmap_pages (How many pages should be mmap-ed to the perf event for
      each CPU. It must be a power of 2.) type: int32 default: 2
    -clear (remove xdpdump from shared array) type: bool default: false
    -cpu (cpu to take dump from) type: int32 default: -1
    -dport (destination port) type: int32 default: 0
    -dst (destination ip address) type: string default: ""
    -duration_ms (how long to take a capture) type: int32 default: -1
    -map_path (path to root jump array) type: string
      default: "/sys/fs/bpf/jmp_eth0"
    -mute (switch off output of received packets) type: bool default: false
    -offset (offset for byte matching) type: int32 default: 0
    -offset_len (length fot the bytematching; up to 4) type: int32 default: 0
    -packet_limit (max number of packets to be written in pcap file)
      type: int32 default: 0
    -pattern (pattern for bytematching; up to 4bytes) type: int64 default: 0
    -pcap_path (path to pcap file) type: string default: ""
    -proto (protocol to match) type: int32 default: 0
    -snaplen (max length of the packet that will be captured (set 0 to capture
      whole packet)) type: int32 default: 0
    -sport (source port) type: int32 default: 0
    -src (source ip address) type: string default: ""
```

#### example 1
capture packets w/ destination port 22 protocol TCP (protocol number 6)
source address 10.0.2.2 and destination address 10.0.2.15
use rootlet's prog array located at /sys/fs/bpf/jmp_enp0s3

```
 sudo ./build/tools/xdpdump/xdpdump -map_path /sys/fs/bpf/jmp_enp0s3 -proto 6 -dport 22 -src 10.0.2.2 -dst 10.0.2.15
src: 10.0.2.2 dst: 10.0.2.15
proto: 6 sport: 52840 dport: 22 pkt size: 90 chunk size: 90

src: 10.0.2.2 dst: 10.0.2.15
proto: 6 sport: 52840 dport: 22 pkt size: 60 chunk size: 60
src: 10.0.2.2 dst: 10.0.2.15
proto: 6 sport: 52840 dport: 22 pkt size: 60 chunk size: 60
src: 10.0.2.2 dst: 10.0.2.15
proto: 6 sport: 52840 dport: 22 pkt size: 60 chunk size: 60
src: 10.0.2.2 dst: 10.0.2.15
proto: 6 sport: 52840 dport: 22 pkt size: 60 chunk size: 60
src: 10.0.2.2 dst: 10.0.2.15
proto: 6 sport: 52840 dport: 22 pkt size: 60 chunk size: 60
src: 10.0.2.2 dst: 10.0.2.15
```

#### example 2
same as above, but also save packets in pcap file located in /tmp/out.pcap.
save only 10 packets and exit, when this number is reached.

```
sudo ./build/tools/xdpdump/xdpdump -map_path /sys/fs/bpf/jmp_enp0s3 -proto 6 -dport 22 -src 10.0.2.2 -dst 10.0.2.15 -pcap_path /tmp/out.pcap -packet_limit 10
src: 10.0.2.2 dst: 10.0.2.15
proto: 6 sport: 52840 dport: 22 pkt size: 90 chunk size: 90
src: 10.0.2.2 dst: 10.0.2.15
proto: 6 sport: 52840 dport: 22 pkt size: 60 chunk size: 60
src: 10.0.2.2 dst: 10.0.2.15
proto: 6 sport: 52840 dport: 22 pkt size: 60 chunk size: 60
src: 10.0.2.2 dst: 10.0.2.15
proto: 6 sport: 52840 dport: 22 pkt size: 60 chunk size: 60
src: 10.0.2.2 dst: 10.0.2.15
proto: 6 sport: 52840 dport: 22 pkt size: 60 chunk size: 60
src: 10.0.2.2 dst: 10.0.2.15
proto: 6 sport: 52840 dport: 22 pkt size: 60 chunk size: 60
src: 10.0.2.2 dst: 10.0.2.15
proto: 6 sport: 52840 dport: 22 pkt size: 60 chunk size: 60
src: 10.0.2.2 dst: 10.0.2.15
proto: 6 sport: 52840 dport: 22 pkt size: 60 chunk size: 60
src: 10.0.2.2 dst: 10.0.2.15
proto: 6 sport: 52840 dport: 22 pkt size: 60 chunk size: 60
src: 10.0.2.2 dst: 10.0.2.15
proto: 6 sport: 52840 dport: 22 pkt size: 60 chunk size: 60
```

you can use tcpdump for reading data from saved pcap file.

```
tcpdump -ennnvvvr /tmp/out.pcap
reading from file /tmp/out.pcap, link-type EN10MB (Ethernet)
09:14:11.715640 52:54:00:12:35:02 > 08:00:27:24:44:6b, ethertype IPv4 (0x0800), length 90: (tos 0x0, ttl 64, id 15580, offset 0, flags [none], proto TCP (6), length 76)
    10.0.2.2.52840 > 10.0.2.15.22: Flags [P.], cksum 0x7060 (correct), seq 39355439:39355475, ack 1894993876, win 65535, length 36
09:14:11.716611 52:54:00:12:35:02 > 08:00:27:24:44:6b, ethertype IPv4 (0x0800), length 60: (tos 0x0, ttl 64, id 15581, offset 0, flags [none], proto TCP (6), length 40)
    10.0.2.2.52840 > 10.0.2.15.22: Flags [.], cksum 0x8026 (correct), seq 36, ack 429, win 65535, length 0
09:14:11.717068 52:54:00:12:35:02 > 08:00:27:24:44:6b, ethertype IPv4 (0x0800), length 60: (tos 0x0, ttl 64, id 15582, offset 0, flags [none], proto TCP (6), length 40)
    10.0.2.2.52840 > 10.0.2.15.22: Flags [.], cksum 0x7fe2 (correct), seq 36, ack 497, win 65535, length 0
09:14:11.717541 52:54:00:12:35:02 > 08:00:27:24:44:6b, ethertype IPv4 (0x0800), length 60: (tos 0x0, ttl 64, id 15583, offset 0, flags [none], proto TCP (6), length 40)
    10.0.2.2.52840 > 10.0.2.15.22: Flags [.], cksum 0x7ed6 (correct), seq 36, ack 765, win 65535, length 0
09:14:11.717770 52:54:00:12:35:02 > 08:00:27:24:44:6b, ethertype IPv4 (0x0800), length 60: (tos 0x0, ttl 64, id 15584, offset 0, flags [none], proto TCP (6), length 40)
    10.0.2.2.52840 > 10.0.2.15.22: Flags [.], cksum 0x7ea2 (correct), seq 36, ack 817, win 65535, length 0
09:14:11.718186 52:54:00:12:35:02 > 08:00:27:24:44:6b, ethertype IPv4 (0x0800), length 60: (tos 0x0, ttl 64, id 15585, offset 0, flags [none], proto TCP (6), length 40)
    10.0.2.2.52840 > 10.0.2.15.22: Flags [.], cksum 0x7da6 (correct), seq 36, ack 1069, win 65535, length 0
09:14:11.718743 52:54:00:12:35:02 > 08:00:27:24:44:6b, ethertype IPv4 (0x0800), length 60: (tos 0x0, ttl 64, id 15586, offset 0, flags [none], proto TCP (6), length 40)
    10.0.2.2.52840 > 10.0.2.15.22: Flags [.], cksum 0x7d0a (correct), seq 36, ack 1225, win 65535, length 0
09:14:11.719199 52:54:00:12:35:02 > 08:00:27:24:44:6b, ethertype IPv4 (0x0800), length 60: (tos 0x0, ttl 64, id 15587, offset 0, flags [none], proto TCP (6), length 40)
    10.0.2.2.52840 > 10.0.2.15.22: Flags [.], cksum 0x7c6e (correct), seq 36, ack 1381, win 65535, length 0
09:14:11.719757 52:54:00:12:35:02 > 08:00:27:24:44:6b, ethertype IPv4 (0x0800), length 60: (tos 0x0, ttl 64, id 15588, offset 0, flags [none], proto TCP (6), length 40)
    10.0.2.2.52840 > 10.0.2.15.22: Flags [.], cksum 0x7bd2 (correct), seq 36, ack 1537, win 65535, length 0
09:14:11.720345 52:54:00:12:35:02 > 08:00:27:24:44:6b, ethertype IPv4 (0x0800), length 60: (tos 0x0, ttl 64, id 15589, offset 0, flags [none], proto TCP (6), length 40)
    10.0.2.2.52840 > 10.0.2.15.22: Flags [.], cksum 0x7b36 (correct), seq 36, ack 1693, win 65535, length 0
```
