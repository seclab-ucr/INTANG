
FAQ
==================
What can I do with INTANG?
------------------------------
With INTANG, your HTTP connections are protected from censor's monitoring. For some reasons, GFW will block the communication between a client and a server for 90 seconds after a sensitive keyword is seen in the HTTP request. You will see in the browser a "Connection has been reset" page once that happens. By using the tool, you can bypass such attacks from GFW. 

Also, you can visit some blocked websites, e.g. facebook.com. Since their servers are not blocked by IP blocking, but only DNS poisoning, our tool can establish a connection to a unpolluted DNS resolver using TCP. 

Why can't I access to Internet after using INTANG?
------------------------------
Since INTANG intercepts HTTP and DNS packets by adding iptables rules, if it is terminated abnormally, it may not be able to remove the iptables rules. If this happens, you will need to manually remove those rules (a simple way is using `iptables -F`, if no other existing rules).

Why some websites become very slow or even can't be opened after using INTANG?
------------------------------
Our censorship evasion strategies are not perfect. They may accidentally close the normal connections on server-side. We are going to develop a more clever algorithm to choose the best strategy for each website you visit. But for now, we only use a weighted random selector to choose strategy. If you cannot visit a website, try to refresh the website with Ctrl-F5, it may use another strategy which works for the website. 

Also, INTANG chooses a random DNS resolver when it starts up, if you feel the DNS resolver is slow, you can change it in dns.c. By default, INTANG will only use the TCP DNS resolver for blocked websites, but you can also change it in main.c.

I'm still experiencing "Connection has been reset".
------------------------------
If you are visiting a blocked website, or using sensitive keywords in HTTP request, it looks like the evasion strategy is not working. Possibly INTANG used "dummy" strategy (which means no strategy) for that connection, you can adjust the weight in strategy.c to disable "dummy" strategy. Or your browser is started before INTANG, so it may have established connections that are not protected by INTANG. Then we recommend you to restart the browser (also restart the backgroud processes of browser). If both methods above don't resolve the problem, maybe the packets injected by INTANG are interfered by your ISP or any firewalls in the path from your machine to the website. You may contact us for further support.

Can I use proxy or VPN together with INTANG at the same time?
------------------------------
No, the mechanism of INTANG decides it is not compatible with any kind of proxy. For this reason, it is not working when using a VM with NAT mode, because most of the VM softwares implement NAT as a proxy. 

