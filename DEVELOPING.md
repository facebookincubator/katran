# DEVELOPING

### Developing of katran

This guide contains information on how you can build and test katran's
BPF forwarding plane and cpp library to control it.

### Formatting:

We are using clang-format for C++ code formatting. Please make sure that code is properly
formatted before sending PR. You can format it with `clang-format -i <path/to/file>`
(if your linux distribution does not have clang-format installed, you can use one from the
deps folder: `./deps/clang/clang+llvm-5.0.0-linux-x86_64-ubuntu16.04/bin/clang-format`)

### Build and compile.

You can build the initial version with `build_katran.sh` script (if you are using
ubuntu 18.04). It will download all required dependencies and build
actual binaries. However, you can build everything separately.

### BPF forwarding plane

To be able to build BPF forwarding plane you need to run
`build_bpf_modules_opensource.sh` from the root of the working directory. It assumes
that you have all dependencies installed and that the linux kernel source code
is located at `deps/linux/` (__Note:__ It is automatically installed there with the script: `build_katran.sh`).
The result of this script will be object files w/ BPF programs, which are going
to be located in `deps/linux/bpfprog/bpf/`. These files are:

1. __`balancer.bpf.o`__ - object file w/ main BPF program for forwarding
2. __`healthchecking_ipip.o`__ - object file w/ BPF program for the forwarding of
healthchecks

### C++ library

To be able to build C++ library (and examples) you need to:

1. create (if it doesn't exist already) __`build dir`__
2. run `cmake ..` inside this __`build dir`__

## Testing

### C++ library
If you are adding new features into C++ library, please make sure that you also submit
unittests for them (all BPF specific calls should be added into `if(!testing_){...}` block
as they require root access (most of the time). You can run unittests manually or w/ ctest
util.

```
$ pwd
$HOME/katran/build/katran/lib/tests
$ ctest
Test project build/katran/lib/tests
    Start 1: IpHelpersTests
1/4 Test #1: IpHelpersTests ...................   Passed    0.00 sec
    Start 2: CHHelpersTests
2/4 Test #2: CHHelpersTests ...................   Passed    0.01 sec
    Start 3: LibKatranTests
3/4 Test #3: LibKatranTests ...................   Passed    0.26 sec
    Start 4: VipTests
4/4 Test #4: VipTests .........................   Passed    0.03 sec

100% tests passed, 0 tests failed out of 4

Total Test time (real) =   0.31 sec
$
```

### BPF

We have developed a special framework for the BPF program testing. It is based on
`bpf_prog_test_run`. This framework allow us to specify predefined test fixtures (input and expected output)
to make sure that for a specified input, the BPF program produces expected output. Test fixtures in our case contain
base64 encoded packets. You can check `katran/lib/testing/fixtures/KatranBaseTestFixtures.h` for examples. To run these tests
you just need to run `./os_run_tester.sh` script (this script requires root privileges).

```
$ ./os_run_tester.sh
++ pwd
++ pwd
+ sudo sh -c '/home/username/katran_oss/build/katran/lib/testing/katran_tester -balancer_prog /home/username/katran_oss/deps/linux/bpfprog/bpf/balancer.bpf.o -test_from_fixtures=true '
E0318 15:21:07.659436 28440 BpfLoader.cpp:144] Can't read section size for index: 2
I0318 15:21:07.659950 28440 BpfLoader.cpp:419] Skipping section: 2 of file: /home/username/katran_oss/deps/linux/bpfprog/bpf/balancer.bpf.o
I0318 15:21:07.692260 28440 BpfLoader.cpp:338] relocation for non existing prog w/ idx 10
I0318 15:21:07.692790 28440 BpfLoader.cpp:338] relocation for non existing prog w/ idx 14
I0318 15:21:07.693243 28440 BpfLoader.cpp:338] relocation for non existing prog w/ idx 16
I0318 15:21:07.693667 28440 BpfLoader.cpp:338] relocation for non existing prog w/ idx 18
I0318 15:21:07.694093 28440 BpfLoader.cpp:338] relocation for non existing prog w/ idx 20
I0318 15:21:07.701683 28440 KatranLb.cpp:378] adding new vip: 10.200.1.1:80:17
I0318 15:21:07.865139 28440 KatranLb.cpp:378] adding new vip: 10.200.1.1:80:6
I0318 15:21:08.022128 28440 KatranLb.cpp:378] adding new vip: 10.200.1.2:0:6
I0318 15:21:08.178966 28440 KatranLb.cpp:378] adding new vip: 10.200.1.4:0:6
I0318 15:21:08.327633 28440 KatranLb.cpp:443] modyfing vip: 10.200.1.4:0:6
I0318 15:21:08.328361 28440 KatranLb.cpp:378] adding new vip: 10.200.1.3:80:6
I0318 15:21:08.481209 28440 KatranLb.cpp:378] adding new vip: fc00:1::1:80:6
I0318 15:21:08.631790 28440 KatranLb.cpp:378] adding new vip: 10.200.1.5:443:17
I0318 15:21:08.632745 28440 KatranLb.cpp:443] modyfing vip: 10.200.1.5:443:17
I0318 15:21:08.788859 28440 KatranLb.cpp:378] adding new vip: fc00:1::2:443:17
I0318 15:21:08.789475 28440 KatranLb.cpp:443] modyfing vip: fc00:1::2:443:17
I0318 15:21:08.938019 28440 XdpTester.cpp:142] Test: packet to UDP based v4 VIP (and v4 real)                     result: Passed
I0318 15:21:08.938712 28440 XdpTester.cpp:142] Test: packet to TCP based v4 VIP (and v4 real)                     result: Passed
I0318 15:21:08.939400 28440 XdpTester.cpp:142] Test: packet to TCP based v4 VIP (and v4 real; any dst ports).     result: Passed
I0318 15:21:08.940088 28440 XdpTester.cpp:142] Test: packet to TCP based v4 VIP (and v6 real)                     result: Passed
I0318 15:21:08.940827 28440 XdpTester.cpp:142] Test: packet to TCP based v6 VIP (and v6 real)                     result: Passed
I0318 15:21:08.941443 28440 XdpTester.cpp:142] Test: v4 ICMP echo-request                                         result: Passed
I0318 15:21:08.941794 28440 XdpTester.cpp:142] Test: v6 ICMP echo-request                                         result: Passed
I0318 15:21:08.942143 28440 XdpTester.cpp:142] Test: v4 ICMP dest-unreachabe fragmentation-needed                 result: Passed
I0318 15:21:08.942488 28440 XdpTester.cpp:142] Test: v6 ICMP packet-too-big                                       result: Passed
I0318 15:21:08.942817 28440 XdpTester.cpp:142] Test: drop of IPv4 packet w/ options                               result: Passed
I0318 15:21:08.943133 28440 XdpTester.cpp:142] Test: drop of IPv4 fragmented packet                               result: Passed
I0318 15:21:08.943462 28440 XdpTester.cpp:142] Test: drop of IPv6 fragmented packet                               result: Passed
I0318 15:21:08.943747 28440 XdpTester.cpp:142] Test: pass of v4 packet with dst not equal to any configured VIP   result: Passed
I0318 15:21:08.944027 28440 XdpTester.cpp:142] Test: pass of v6 packet with dst not equal to any configured VIP   result: Passed
I0318 15:21:08.944326 28440 XdpTester.cpp:142] Test: pass of arp packet                                           result: Passed
I0318 15:21:08.944638 28440 XdpTester.cpp:142] Test: LRU hit                                                      result: Passed
I0318 15:21:08.944896 28440 XdpTester.cpp:142] Test: packet #1 dst port hashing only                              result: Passed
I0318 15:21:08.945171 28440 XdpTester.cpp:142] Test: packet #2 dst port hashing only                              result: Passed
I0318 15:21:08.945444 28440 XdpTester.cpp:142] Test: ipinip packet                                                result: Passed
I0318 15:21:08.945725 28440 XdpTester.cpp:142] Test: ipv6inipv6 packet                                            result: Passed
I0318 15:21:08.945996 28440 XdpTester.cpp:142] Test: ipv4inipv6 packet                                            result: Passed
I0318 15:21:08.946280 28440 XdpTester.cpp:142] Test: QUIC: long header. Client Initial type                       result: Passed
I0318 15:21:08.946561 28440 XdpTester.cpp:142] Test: QUIC: long header. 0-RTT Protected                           result: Passed
I0318 15:21:08.946645 28440 XdpTester.cpp:142] Test: QUIC: long header. v4 vip v6 real                            result: Passed
I0318 15:21:08.946728 28440 XdpTester.cpp:142] Test: QUIC: long header. v6 vip v6 real                            result: Passed
I0318 15:21:08.946970 28440 XdpTester.cpp:142] Test: QUIC: short header. no connection id                         result: Passed
I0318 15:21:08.947049 28440 XdpTester.cpp:142] Test: QUIC: short header w/ connection id                          result: Passed
I0318 15:21:08.947124 28440 XdpTester.cpp:142] Test: QUIC: short header w/ connection id but non-existing mapping result: Passed
I0318 15:21:08.947191 28440 katran_tester.cpp:135] Testing counter's sanity. Printing on errors only
I0318 15:21:08.947327 28440 katran_tester.cpp:156] Testing of counters is complite
$
```
