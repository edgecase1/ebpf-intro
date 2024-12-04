This program traces `exec` calls via the `sched/sched_process_exec` tracepoint.

Add a 
```
sudo bpftool map update name pidns_maps key 0x5c 0x03 0 0xf0 value 1 0 0 0

0x5c 0x03 0 0xf0 = 0xf000035c = -268434596 = 4026532700
```