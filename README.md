# eBPF Packet Latency Measurement Tool

A minimal eBPF-based tool to measure packet processing latency on a specified network interface. It consists of:

- A kernel-space eBPF program (`delay.ebpf.c`)
- A user-space program (`user.ebpf`) that handles loading, attaching, and cleanup

> **Note:** Currently, the tool supports only **IPv4** traffic and is limited to **UDP** and **TCP** protocols.
---

### Compilation

Make sure `clang` and `libbpf` are installed on your system.

**_Before compiling_**

Before compiling `user.ebpf.c`, edit the following line to specify your network interface:

`#define NET_INTERFACE "your_net_interface_name"`

#### Compile the eBPF program:
```
clang -v -O2 -g -Wall -target bpf -c delay.ebpf.c -o delay.ebpf.o

clang -O2 -g -Wall user.ebpf.c -o user.ebpf -lbpf
```

#### Run the Program

After successful compilation, run the program with `sudo ./user.ebpf`

This will:
- Load the eBPF program
- Attach it to the specified network interface
- Start tracing
- Automatically detach and clean up on exit

#### View Latency Output

To see the trace output (latency logs), in a separate terminal run:

`sudo cat /sys/kernel/debug/tracing/trace_pipe`


⚠️ **Note:** You may see the following message when attaching the eBPF program:

```
libbpf: Kernel error message: Exclusivity flag on, cannot modify
```
This can be safely ignored. It does not affect functionality.

📌 **Important Note**

This tool provides statistical insights into packet processing delays, rather than exact per-packet tracing.
It identifies packets using IP address and port information only, not unique packet identifiers. As a result, measurements may include approximation or overlap between different packets sharing the same source IP address and port number (especially under high throughput or connection reuse).

The goal is to offer a lightweight, low-overhead view of network processing behavior across the system, suitable for performance tuning and general latency profiling — not for precise, per-packet tracking.
