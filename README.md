
Introduction
==================
INTANG is research project for circumventing the "TCP reset attack" from the Great Firewall of China (GFW) by disrupting/desynchronizing the TCP Control Block (TCB) on the censorship devices. INTANG runs as a client-side only tool in background to protect the TCP connections from being interfered (or even monitored) by the GFW. It works on TCP/IP layers instead of application layer, thus considered more general and can help all application layer protocols, e.g. HTTP, DNS over TCP, OpenVPN, Tor, evading censorship. It can also be run on a proxy to make the deployment easier for those who are incapable of running INTANG (using OSes other than Linux or doesn't have root privillige).

Platform
==================
Linux (must has netfilter supported in kernel)

*Tested with Ubuntu 12.04/14.04/16.04.*

Dependencies
==================
* libnetfilter-queue-dev
* libnfnetlink-dev
* redis-server
* libhiredis-dev
* libev-dev
* python-redis (optional)
* python-scapy (optional)

Compilation
==================
1. Install prerequisite packages:
```shell
sudo apt-get update
sudo apt-get install libnetfilter-queue-dev libnfnetlink-dev redis-server libhiredis-dev libev-dev python-redis python-scapy
```
or
```shell
./install_deps.sh
```
2. Compile:
```shell
make
```
And the binary will be located under bin folder.

How to Run
==================
1. Use `run.sh` to start the daemon. Logs are by default written to /var/log/intangd.log. If you want to test a specific strategy, use `run.sh <strategy ID>`. Strategy IDs can be checked with `run.sh -h`.
2. Use `stop.sh` to stop the daemon. It simply send SIGINT signal to the daemon.

**The daemon needs root privilege to run.**
**If you are using Virtual Machine, you'll need to configure the networks in Bridge Mode.**

Source Code Organization
==================
```
/
├── main.c                                      Entry point and Main Thread
├── globals.h                                   Global constants
├── protocol.h                                  Definition of protocol(IP/TCP/UDP/DNS) headers
├── memcache.c                                  In-memory cache
├── cache.c                                     Cache Thread
├── order.c                                     Shared in-memory queue between Main Thread and Cache Thread
├── redis.c                                     Communication interfaces to Redis
├── dns.c                                       DNS Thread
├── dnscli.c                                    Functions for Main Thread to send requests to DNS Thread.
├── logging.c                                   Logging functions
├── strategy.c                                  Strategy registration and selection
├── discrepancy.c                               Implementation of low-level "insertion packets", such as wrong checksum
├── socket.c                                    Socket related functions, sending crafted packets
├── feedback.c                                  Log uploading functions
├── helper.c                                    Shared global helper functions 
├── ttl_probing.c                               Functions for TTL probing and maintaining
├── test.c                                      Testing functions
├── run.sh/stop.sh                              Run/Stop INTANG
├── distgen.sh                                  Generating distributable code tarball
├── strategies/ 
    ├── dummy.c                                 Dummy strategy (do nothing)
    ├── rst_***.c                               TCB teardown strategies
    ├── do_***.c                                Buffer prefilling(data overlapping) strategies
    ├── reverse_tcb.c                           TCB reversal strategy
    ├── multiple_syn.c                          Multiple SYN (Resync-Desync) strategy
    ├── mixed_***.c                             Combined strategies. 
    ├── ...
├── tools/                                      Folder containing python scripts for data analysis
    ├── dump_stats.py                           Show success rates of strategies by reading from Redis. (INTANG must be running)
    ├── dump_stats_from_log.py                  Show success rates of strategies by reading from log.
    ├── ...
```

Disclaimer
==================
INTANG is a reasearch-oriented project. Anyone using it should be aware of the potential risks and responsible for his/her own actions against the censorship authority.

Contact
==================
Any questions could be direct to intang.box@gmail.com

Paper Published
==================
Zhongjie Wang, Yue Cao, Zhiyun Qian, Chengyu Song, and Srikanth V. Krishnamurthy. 2017. Your State is Not Mine: A Closer Look at Evading Stateful Internet Censorship. In Proceedings of IMC ’17. ACM, New York,NY, USA, 14 pages. https://doi.org/10.1145/3131365.3131374

FAQ
==================
Please see [FAQ](FAQ.md) page.

