

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cache.h"
#include "protocol.h"
#include "socket.h"
#include "redis.h"


/*
void test_cache()
{
    struct fourtuple f1, f2, f3;
    f1.saddr = 1921388123;
    f1.daddr = 231948923;
    f1.sport = 80;
    f1.dport = 3992;
    icache_set(&f1, 2);
    icache_set(&f1, 3);
    f2.saddr = 77777723;
    f2.daddr = 231948923;
    f2.sport = 80;
    f2.dport = 1200;
    icache_set(&f2, 0);
    f3.saddr = 77777723;
    f3.daddr = 231948923;
    f3.sport = 80;
    f3.dport = 1200;
    icache_set(&f3, 5);

    int ret, val;
    ret = icache_get(&f1, &val);
    if (ret == ENTRY_FOUND) {
        printf("FOUND. %d\n", val);
    } else {
        printf("Entry not found.\n");
    }

    sleep(3);
    ret = icache_get(&f1, &val);
    if (ret == ENTRY_FOUND) {
        printf("FOUND. %d\n", val);
    } else {
        printf("Entry not found.\n");
    }

    dump_icache();

}
*/

void test_redis()
{
    int val;
    char buf[100];
    set_str("foo", "100");
    get_str("foo", buf, 100);
    printf("foo: %s\n", buf);

    incr("bar");
    val = get_int("bar");
    printf("bar: %d\n", val);

    get_str("abc", buf, 100);
    printf("abc: %s\n", buf);

    val = get_int("abc");
    printf("abc: %d\n", val);
}

void test_checksum()
{
    char payload[1000] = "GET /search?q=%E6%B3%95%E8%BD%AE%E5%8A%9F HTTP/1.1\r\nHOST: www.douban.com\r\nUser-Agent: Chrome\r\n\r\n";
    printf("Testing checksum\n");
    struct send_tcp_vars vars;
    strcpy(vars.src_ip, "192.168.1.9");
    strcpy(vars.dst_ip, "74.125.196.156");
    vars.src_port = 38324;
    vars.dst_port = 80;
    vars.seq_num = htonl(345678);
    vars.flags = TCP_SYN;
    vars.win_size = 0;
    vars.ttl = 128;
    vars.tcp_opt[0] = 0xfe;
    vars.tcp_opt[1] = 0x04;
    vars.tcp_opt[2] = 0xf9;
    vars.tcp_opt[3] = 0x89;
    vars.tcp_opt_len = 4;
    vars.payload[0] = 0;
    strncat(vars.payload, payload, 1000);
    vars.payload_len = strlen(payload);
    send_tcp(&vars);
}


int test_main()
{
    //test_redis();
    test_checksum();
    return 0;
}
