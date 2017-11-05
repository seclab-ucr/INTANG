
FAQ
==================
What can I do with INTANG?
------------------------------
INTANG aims at evading the GFW's TCP connection reset attacks. Connection reset is a commonly used technique by the GFW to shutdown connections and has been found working on protocols like HTTP/VPN/Tor/DNS over TCP, etc. For example, when you are visiting a foreign website and sees a "Connection has been reset" error page in the browser, it's possibly caused by the GFW. Also, it happens sometimes when you are connecting to a VPN or Tor relay outside China. 

INTANG works at TCP-layer and disrupt the TCP state machine on the GFW. So it can help all application protocols based on TCP evade censorship. With INTANG, your TCP connections are protected from censor's monitoring. 
You can visit some blocked websites, e.g. wordpress.com, dropbox.com, etc. Since their servers are not IP-blocked by the GFW, but suffering from DNS poisoning and connection reset. Our tool can also establish a connection to a unpolluted DNS resolver using TCP to evade DNS poisoning. 
However, websites such as Google, Facebook, Twitter, etc., are IP-blocked by the GFW, so they are not accessible even with INTANG. IP-blocking works at IP layer, which is more low-level than TCP layer. There are also some recent research projects called Refraction Networking aiming at evading IP-blocking. 

Why can't I access to Internet after using INTANG?
------------------------------
Since INTANG intercepts HTTP and DNS packets by adding iptables rules, if it is terminated abnormally, it may not be able to remove the iptables rules. If this happens, you will need to manually remove those rules (a simple way is using `iptables -F`, if no other existing rules).

Why can't some websites be visited after using INTANG?
------------------------------
Our censorship evasion strategies are not perfect. They may accidentally terminate the normal connections on server-side. We are working on finding more effective discrepancies to reduce this side-effect. By now, INTANG has an automatic strategy selection algorithm, which can switch between a bunch of strategies. In case one strategy fails often, it will turn to alternative strategies. Different strategies work better for different servers, so it may eventually find and save the best strategy for each server.

Why do the webpages load slower after using INTANG?
------------------------------
INTANG chooses a random DNS resolver when it starts up, if you feel the DNS resolver is slow, you can use other unpolluted DNS resolvers by modifying dns.c. By default, INTANG only delegate DNS resolving for websites in our list. But you may also choose to do DNS delegation for all websites or turn it off completely by modifying main.c. 

I'm still experiencing "Connection has been reset".
------------------------------
If you are visiting a blocked website, or using sensitive keywords in HTTP request, it looks like the evasion strategy is not working. Possibly the strategy choosed by INTANG is not effective for the certain server, and you may try connecting the website again later after a certain period (i.e. 90 seconds). INTANG will automatically choose the best strategy for each server based on historical results. In another case, if your browser/application is started before INTANG, it may have established some connections that are not protected by INTANG. Then we recommend you to restart the browser/application. If the problem persists, you may submit a feedback through email. We will try our best to answer the problem.

