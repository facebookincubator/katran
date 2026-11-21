# DEVELOPING

### Developing of katran

This guide contains information on how you can build and test katran's
BPF forwarding plane and cpp library to control it.

### Formatting:

We are using clang-format for C++ code formatting. Please make sure that code is properly
formatted before sending PR. You can format it with `clang-format -i <path/to/file>`.

### Build and compile.

katran is a plain CMake project, and [`README.md`](README.md#installation) lists
the packages it needs. From the root of the repository:

```
$ cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_TESTS=ON
$ cmake --build build -j "$(nproc)"
```

If folly is not installed, the first build also fetches and compiles it, which
takes a while.

### BPF forwarding plane

The build compiles the BPF programs with clang into `build/bpf/`. The main ones are:

1. __`balancer.bpf.o`__ - object file w/ main BPF program for forwarding
2. __`healthchecking_ipip.o`__ - object file w/ BPF program for the forwarding of
healthchecks

`katran/lib/bpf/CMakeLists.txt` lists them with their defines.
`-DKATRAN_BUILD_BPF=OFF` skips them.

## Testing

### C++ library
If you are adding new features into C++ library, please make sure that you also submit
unittests for them (all BPF specific calls should be added into `if(!testing_){...}` block
as they require root access (most of the time). ctest runs them:

```
$ ctest --test-dir build
```

### BPF

We have developed a special framework for the BPF program testing. It is based on
`bpf_prog_test_run`. This framework allow us to specify predefined test fixtures (input and expected output)
to make sure that for a specified input, the BPF program produces expected output. Test fixtures in our case contain
base64 encoded packets. You can check `katran/lib/testing/fixtures/KatranBaseTestFixtures.h` for examples. These tests
load the programs into the kernel, so they need root:

```
$ sudo ctest --test-dir build -L bpf --output-on-failure
```

They run `katran_tester` and `xdpdecap_tester` on test builds of the balancer and
decap programs, and print a `result: Passed` or `result: Failed` line for each
fixture. `./os_run_tester.sh` runs the balancer fixtures directly.
