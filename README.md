
Intro
==================
INTANG is research project for circumventing the TCP reset attack from the Great Firewall of China. 
urrently an ongoing research project for censorship circumvention. It will runs as a daemon on clients' machines and try to avoid TCP RST attacks carried by censorship systems. Especially, it can bypass GFW's HTTP sensitive content filtering and DNS poisoning. 

Platform
==================
Linux (supports netfilter in kernel)

**We strongly recommend using Ubuntu 12.04+**

Dependencies
==================
* libnetfilter-queue-dev
* libnfnetlink-dev
* redis-server
* libhiredis-dev
* libev-dev
* python-redis
* python-scapy

Installation
==================
1. Install prerequisite packages:
```shell
sudo apt-get update
sudo apt-get install libnetfilter-queue-dev libnfnetlink-dev redis-server libhiredis-dev libev-dev python-redis python-scapy
```
or
```shell
./install.sh
```
2. Compile:
```shell
make
```

How to Run
==================
1. Use *run.sh* to start the daemon. Logs are redirected to /var/log/intangd.log.
2. Use *stop.sh* to stop the daemon. It simply send SIGINT signal to the daemon.

**The daemon needs root privilege to run.**
**If you are using Virtual Machine, please use Bridge Mode for network**

Source Code Organization
==================
```
/
├── *.md                                        Documentation
├── main.c                                      Entry point
├── globals.h                                   Global constants
├── protocol.h                                  Definition of protocol(IP/TCP/UDP/DNS) headers
├── memcache.c                                  In-memory cache used by Main Thread
├── cache.c                                     Cache Thread
├── order.c                                     Shared in-memory queue between Main Thread and Cache Thread
├── redis.c                                     Communication interfaces to Redis
├── dns.c                                       DNS Thread
├── dnscli.c                                    Functions for Main Thread to send requests to DNS Thread.
├── logging.c                                   Logging functions
├── strategy.c                                  Strategy registration and selection
├── feedback.c                                  Automatically log uploading
├── socket.c                                    Socket related functions, sending crafted packets
├── feedback.c                                  Automatically log uploading
├── helper.c                                    Some shared public functions 
├── ttl_probing.c                               Functions for TTL probing
├── test.c                                      Test functions
├── run.sh/stop.sh                              Run/Stop INTANG
├── install.sh/distgen.sh                       Shell scripts, for installation, generating distribution package
├── <Strategies>                                dummy.c is dummy strategy(do nothing), rst_***.c are TCB teardown strategies, do_***.c are buffer prefilling(data overlapping strategies, reverse_tcb.c is TCB reversal strategy, multiple_syn.c is multiple SYN strategy, mixed_***.c are combined strategies. 
├── tools/                                      Python scripts for data analysis and presentation
    ├── dump_stats.py                           Show success rate of strategies by reading from Redis. (INTANG must be running)
    ├── dump_stats_from_log.py                  Show success rate of strategies by reading from log.
    ├── ...
```

Execution Process
==================
There're three threads started in main() function, Main Thread, Cache Thread, and DNS Thread. Main Thread is the packet-loop thread, which handles packets entering the netfilter queue. Cache Thread interacts with a in-memory data storage, Redis, to maintain necessary states of the connections related to our interests. DNS Thread takes care of sending and receiving DNS requests and responses over TCP. The latter two thread takes out the time consuming tasks from Main Thread. 

Anti RST Injection
==================
The program will protect normal HTTP traffic towards port number 80.

Anti DNS Poisoning
==================
The program will automatically detect DNS poisoning and try to get the authentic IP addresses. Only DNS requests to port number 53 will be affected. 

Declaration
==================
INTANG is used for research purpose, it will try to collect some logs for analysis and diagnosis. We appreciate for your understanding and support. 

Contact
==================
intang.box@gmail.com

Paper published
==================
Zhongjie Wang, Yue Cao, Zhiyun Qian, Chengyu Song, and Srikanth V. Krishnamurthy. 2017. Your State is Not Mine: A Closer Look at Evading Stateful Internet Censorship. In Proceedings of IMC ’17. ACM, New York,NY, USA, 14 pages. https://doi.org/10.1145/3131365.3131374

FAQ
==================
Please see [FAQ](FAQ.md) page.

