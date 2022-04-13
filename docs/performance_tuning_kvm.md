# Performance Tuning

## Introduction

This document gives an overview of various parameters that can be configured to achieve maximum performance efficiency. 


## Isolating the CPU cores

When using a server with muliple cores, it would be suggested to isolate some of the cores and reserve them the Guest VMs.

In the example, the system uses  a Intel® Xeon® processor with 48 cores.

Add the below line in `/etc/default/grub` to isolate 16 cores (32-47)

```sh
GRUB_CMDLINE_LINUX_DEFAULT="isolcpus=32-47 nohz_full=32-47 rcu_nocbs=32-47"
```

```sh
sudo update-grub
```

## Optimizing QEMU Performance

The QEMU process is used to load the Guest VM to run the OpenVINO(TM) Security Add-on. The reserved cores can now be used to pin the QEMU vcpu threads.

In this example, the Guest VM is launched with the following options:
```sh
qemu-system-x86_64 -m 8192 -enable-kvm -cpu host -smp 4,sockets=1,cores=4,threads=1 ...
```


To find vcpu threads, you use `ps` command to find PID of QEMU process and `pstree` command for threads launched from QEMU process.

```sh
ps ea
```


```sh
    PID TTY      STAT   TIME COMMAND
  27596 pts/1    Sl+    0:23 qemu-system-x86_64 -m 8192 -enable-kvm -cpu host -smp 4,sockets=1,cores=4,threads=1 ...
```

Run `pstree` with `-p` and the PID to find all threads launched from QEMU.

```sh
pstree -p 27596
```

```sh
qemu-system-x86(27596)─┬─{qemu-system-x86}(27597)
                       ├─{qemu-system-x86}(27609)
                       ├─{qemu-system-x86}(27611)
                       ├─{qemu-system-x86}(27612)
                       ├─{qemu-system-x86}(27613)
                       └─{qemu-system-x86}(27615)
```


Set the affinity by using `taskset` command to pin vcpu threads. The vcpu threads is listed from the second entry and later. In this example, assign PID 27609 to core 43, PID 27611 to core 44 and so on.


```sh
taskset -pc  43  27609
```

```sh
pid 27609's current affinity list: 0-31
pid 27609's new affinity list: 43
```

```sh
taskset -pc  44  27611
```

```sh
pid 27611's current affinity list: 0-31
pid 27611's new affinity list: 44
```

```sh
taskset -pc  45  27612
```

```
pid 27612's current affinity list: 0-31
pid 27612's new affinity list: 45
```
    
```sh
taskset -pc  46  27613
```

```sh
pid 27613's current affinity list: 0-31
pid 27613's new affinity list: 46
```

```sh
taskset -pc  47  27615
```

```sh
pid 27615's current affinity list: 0-31
pid 27615's new affinity list: 47
```


## Reference

* [Best pinning strategy for latency/performance trade-off](https://www.redhat.com/archives/vfio-users/2017-February/msg00010.html)
