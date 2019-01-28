# start_katran
this tool helps to start katran server (works w/ GRPs server only).
on startup it is:
 * discovers mac address of default gateway (using ipv4 address)
 * discovers server topology (how many cpus, cpu to NUMA mapping)
 * by default affinitize NIC w/ specified strategy

currently supported strategies for affinitization:
 * sequential - IRQ affinitized to cpu in in sequentially
 * same-node - IRQ affinitized to CPU in NUMA node 0 only
 * all-nodes - IRQ affinitized to all NUMA nodes one by one 

This tool also could do NIC affinitization w/o starting katran.
Intended use case:
1) run this tool on server startup to do NIC affinitization
w/o starting katran (by specifying -affinitize and -affinitize_only flags)
2) run katran w/ the same strategy as in 1 and w/ -run flag

in this order we wont override NIC's IRQ affinity on every katran's restart

### example of usage.
```
Usage of ./start_katran:
  -affinitize
        affinitize nic by specified strategy
  -affinitize_only
        run only affinitizing logic and exit. do not start katran
  -balancer_bpf string
        Path to balancer bpf prog
  -binary string
        Path to katran_grpc_server
  -enable_hc
        Enable healthchecking bpf prog
  -hc_bpf string
        Path to healthchecking bpf prog
  -intf string
        interface where to attach XDP program (default "enp0s3")
  -ipip6_intf string
        name of the ipip6 interface for healthchecking (default "ipip60")
  -ipip_intf string
        name of the ipip interface for healthchecking (default "ipip0")
  -lru_size int
        size of connection table in entries (default 1000000)
  -map_path string
        path to bpf root array for shared mode
  -map_pos int
        position in shared bpf root array (default 2)
  -priority int
        priority of healthchecking program (default 2307)
  -run
        should we run
  -shutdown_delay int
        sleep timeout before removing xdp prog on shutdown (default 1000)
  -strategy int
        how to affinitize NIC. 0 - sequentaly, 1 - same node, 2 - all nodes (default 2)
```

almost all flags are one to one mapping to CLI flags of katran_server and have the same meaning
few exceptions are:
 * -affinitize = discover CPU topology and write IRQ affinitiy. false by default
 * -affinitize_only = dont try to start katran and do IRQ affinity only
 * -strategy = which IRQ to CPU mapping strategy to use
 * -run (default false) = by default we run in "dryrun" mode. we wont start katran w/o this flag

### example of output on start:
```
sudo ./start_katran -affinitize -balancer_bpf ~/katran/deps/bpfprog/bpf/balancer_kern.o -binary ~/katran/build/example_grpc/katran_server_grpc -map_path /sys/fs/bpf/jmp_enp0s3 -lru_size 1000 -run
number of CPUs  3
2019/01/28 14:19:51 affinitizing irq 19 to cpu 0 mask 00000001
number of CPUs  3
number of CPUs  3
-balancer_prog=/home/tehnerd/katran/deps/bpfprog/bpf/balancer_kern.o -intf=enp0s3 -hc_forwarding=false -map_path=/sys/fs/bpf/jmp_enp0s3 -prog_pos=2 -ipip_intf=ipip0 -ipip6_intf=ipip60 -priority=2307 -lru_size=1000 -shutdown_delay=1000 -forwarding_cores=0 -numa_nodes=0
2019/01/28 14:19:51 cannot reach katran server. retrying in one second
I0128 14:19:51.431486   391 KatranGrpcService.cpp:67] Starting Katran
E0128 14:19:51.431856   391 BpfLoader.cpp:166] Can't read section size for index: 2
I0128 14:19:51.431871   391 BpfLoader.cpp:448] Skipping section: 2 of file: /home/tehnerd/katran/deps/bpfprog/bpf/balancer_kern.o
I0128 14:19:51.485374   391 BpfLoader.cpp:367] relocation for non existing prog w/ idx 10
I0128 14:19:51.485419   391 BpfLoader.cpp:367] relocation for non existing prog w/ idx 14
I0128 14:19:51.485424   391 BpfLoader.cpp:367] relocation for non existing prog w/ idx 16
I0128 14:19:51.485430   391 BpfLoader.cpp:367] relocation for non existing prog w/ idx 18
I0128 14:19:51.485432   391 BpfLoader.cpp:367] relocation for non existing prog w/ idx 20
E0128 14:19:51.504796   391 BpfLoader.cpp:103] Can't find map w/ name: lpm_src_v4
E0128 14:19:51.504853   391 BpfLoader.cpp:103] Can't find map w/ name: decap_dst
Server listening on 0.0.0.0:50051
2019/01/28 14:19:52 cannot reach katran server. retrying in one second
2019/01/28 14:19:53 Mac address is 52:54:00:12:35:02:
2019/01/28 14:19:53 katran is up and running
```
