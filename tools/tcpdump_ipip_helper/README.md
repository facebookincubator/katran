# tcpdump_ipip_helper
this is a simple script which helps to create filters for tcpdump to match on
fields from inner ip packet. currently we can match src/dst/protocol/ports
### example of usage.
```
usage: tcpdump_ipip_helper.py [-h] [-m {4,6,46}] [-s SRC] [-d DST] [-p PROTO]
                              [--sport SPORT] [--dport DPORT]

this is a tool which helps to create a filter to match fields from internal
header of IPIP packet

optional arguments:
  -h, --help            show this help message and exit
  -m {4,6,46}, --mode {4,6,46}
                        mode of the filter. possible values: 4 (for ipip) 6
                        (for ip6ip6), 46 (for ip4ip6)
  -s SRC, --src SRC     src ip address of internal packet. could be ipv4 or
                        ipv6
  -d DST, --dst DST     dst ip address of internal packet. could be ipv4 or
                        ipv6
  -p PROTO, --proto PROTO
                        protocol of internal packet. must be a number. e.g. 6
                        for tcp or 17 for udp
  --sport SPORT         src port of internal packet (e.g. if it's udp or tcp)
  --dport DPORT         dst port of internal packet (e.g. if it's udp or tcp)
```
as output you will have a filter for tcpdump command

#### example 1
create a filter to match inner packet w/ dst 10.0.0.1 TCP and destination
port 22. for ipv4inipv6 encapsulation:

```
./tcpdump_ipip_helper.py -m 4 -d 10.0.0.1 -p 6 --dport 22
"((ip[36:4] == 0x0A000001 ) and (ip[29:1] == 6 ) and (ip[42:2] == 22 ))"
```

no you can use this filter w/ tcpdump. e.g.
```
tcpdump -ni eth0 "((ip[36:4] == 0x0A000001 ) and (ip[29:1] == 6 ) and (ip[42:2] == 22 ))"
```

### example 2
create a filter to match inner packet w/ dst fc00::1 UDP and source port 10000

```
./tcpdump_ipip_helper.py -m 6 -d fc00::1 -p 17 --sport 10000
"((ip6[64:4] == 0xFC000000 ) and (ip6[68:4] == 0x0000 ) and (ip6[72:4] == 0x0000 ) and (ip6[76:4] == 0x0001 ) and (ip6[46:1] == 17 ) and (ip6[80:2] == 10000 ))"
```
