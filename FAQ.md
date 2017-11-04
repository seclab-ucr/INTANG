
FAQ
==================
What can I do with INTANG?
------------------------------
With INTANG, your HTTP connections are protected from censor's monitoring. For some reasons, GFW will block the communication between a client and a server for 90 seconds after a sensitive keyword is seen in the HTTP request. You will see in the browser a "Connection has been reset" page once that happens. By using the tool, you can bypass such kind of attacks from GFW. 

Also, you can visit some blocked websites, e.g. wordpress.com, dropbox.com, etc. Since their servers are not blocked by IP blocking, but only DNS poisoning, our tool can establish a connection to a unpolluted DNS resolver using TCP. 

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

