
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <hiredis/hiredis.h>
#include <hiredis/async.h>
#include <hiredis/adapters/libev.h>

#include "logging.h"
#include "protocol.h"
#include "cache.h"


#define REDIS_SERVER_IP "127.0.0.1"
#define REDIS_SERVER_PORT 6389
#define REIDS_TOKEN "38rh3fF%(!"


static redisContext *ctx;
static redisAsyncContext *actx;


void delete_redis_db()
{
    int ret = remove("/usr/local/share/intangd/dump.rdb");
    if (ret == -1)
    {
        log_warn("Failed to delete redis db. errno: %d", errno);
    }
}

/*************
 * Callbacks *
 *************/

void on_connect(const redisAsyncContext *ac, int status) {
    if (status != REDIS_OK) {
        log_error("Error: %s", ac->errstr);
        return;
    }
    log_info("Async connection built successfully.");
}

void on_disconnect(const redisAsyncContext *ac, int status) {
    if (status != REDIS_OK) {
        log_error("Error: %s", ac->errstr);
        return;
    }
    log_info("Async connection disconnected...");
}

void on_expire(redisAsyncContext *ac, void *r, void *privdata) {
    int i;
    redisReply *reply = r;
    if (reply == NULL) return;
    if (reply->type == REDIS_REPLY_ARRAY && strcmp(reply->element[0]->str, "message") == 0) {
        if (reply->elements == 3) {
            log_debugv("expired: %s", reply->element[2]->str);
            on_request_expire(reply->element[2]->str);
        }
        else {
            log_warn("on_expire: number of element is not 3. (%d)", reply->elements);
        }
    }   
}


/**********************************************/

void build_sync_conn()
{
    if (ctx) {
        redisFree(ctx);
    }
    log_info("Building sync connection with redis server.");

    struct timeval timeout = { 1, 500000 }; // 1.5 seconds
    do {
        ctx = redisConnectWithTimeout(REDIS_SERVER_IP, REDIS_SERVER_PORT, timeout);
        if (ctx == NULL || ctx->err) {
            if (ctx) {
                log_error("redisConnectWithTimeout fails: %s", ctx->errstr);
                redisFree(ctx);
            } else {
                log_error("redisConnectWithTimeout fails: can't allocate redis context");
            }
        }
    }
    while (ctx == NULL || ctx->err);
    log_info("Sync connection built successfully.");
}

void build_async_conn()
{
    if (actx) {
        redisAsyncDisconnect(actx);
    }

    actx = redisAsyncConnect(REDIS_SERVER_IP, REDIS_SERVER_PORT);
    if (actx == NULL || actx->err) {
        if (actx) {
            log_error("redisAsyncConnect fails: %s", actx->errstr);
            //redisFree(actx);
        } else {
            log_error("redisAsyncConnect fails: can't allocate redis context");
        }
        return;
    }

    redisLibevAttach(EV_DEFAULT_ actx);
    redisAsyncSetConnectCallback(actx, on_connect);
    redisAsyncSetDisconnectCallback(actx, on_disconnect);
    redisAsyncCommand(actx, on_expire, NULL, "SUBSCRIBE __keyevent@0__:expired");
}

int connect_to_redis()
{
    build_sync_conn();

    build_async_conn();

    return 0;
}

int disconnect_from_redis()
{
    if (ctx != NULL) {
        redisFree(ctx);
    }
    return 0;
}

void get_str(const char *key, char *val, size_t len)
{
    redisReply *reply;
    reply = redisCommand(ctx, "GET %s", key);

    val[0] = 0;
    if (reply == NULL) 
    {
        log_error("get_str fails: %s", ctx->errstr);
        // handle error
        return;
    }
    if (reply->type == REDIS_REPLY_NIL) {
        log_debugv("get_str: key not found: %s", key);
    }
    else if (reply->type == REDIS_REPLY_STRING) {
        strncat(val, reply->str, len);
        log_debugv("get_str: %s %s", key, val);
    }
    else {
        log_warn("get_str: unexpected reply type: %d", reply->type);
    }
    
    freeReplyObject(reply);
}

int get_int(const char *key)
{
    int val = 0;

    redisReply *reply;
    reply = redisCommand(ctx, "GET %s", key);
    if (reply == NULL) 
    {
        log_error("get_int fails: %s", ctx->errstr);
        // handle error
        return 0;
    }
    if (reply->type == REDIS_REPLY_NIL) {
        val = 0;
        log_debugv("get_int: key not found: %s", key);
    }
    else if (reply->type == REDIS_REPLY_INTEGER) {
        val = reply->integer;
        log_debugv("get_int: %s %d", key, val);
    }
    else if (reply->type == REDIS_REPLY_STRING) {
        val = strtol(reply->str, NULL, 10);
        log_debugv("get_int: %s %d", key, val);
    }
    else {
        log_warn("get_int: unexpected reply type: %d", reply->type);
    }

    freeReplyObject(reply);
    return val;
}

void set_str(const char *key, const char *val)
{
    redisReply *reply;
    reply = redisCommand(ctx, "SET %s %s", key, val);
    if (reply == NULL)
    {
        log_error("set_str fails: %s", ctx->errstr);
        // handle error
        return;
    }
    if (reply->type == REDIS_REPLY_STATUS) {
        log_debugv("set_str %s %s %s", key, val, reply->str);
    }
    else {
        log_warn("set_str: unexpected reply type: %d", reply->type);
    }

    freeReplyObject(reply);
}

void set_int(const char *key, int val)
{
    redisReply *reply;
    reply = redisCommand(ctx, "SET %s %d", key, val);
    if (reply == NULL)
    {
        log_error("set_int fails: %s", ctx->errstr);
        // handle error
        return;
    }
    if (reply->type == REDIS_REPLY_STATUS) {
        log_debugv("set_int %s %d %s", key, val, reply->str);
    }
    else {
        log_warn("set_int: unexpected reply type: %d", reply->type);
    }

    freeReplyObject(reply);
}

void set_str_ex(const char *key, const char *val, int timeout)
{
    redisReply *reply;
    reply = redisCommand(ctx, "SETEX %s %d %s", key, timeout, val);
    if (reply == NULL)
    {
        log_error("set_str_ex fails: %s", ctx->errstr);
        // handle error
        return;
    }
    if (reply->type == REDIS_REPLY_STATUS) {
        log_debugv("set_str_ex %s %s %s", key, val, reply->str);
    }
    else {
        log_warn("set_str_ex: unexpected reply type: %d", reply->type);
    }

    freeReplyObject(reply);
}

void set_int_ex(const char *key, int val, int timeout)
{
    redisReply *reply;
    reply = redisCommand(ctx, "SETEX %s %d %d", key, timeout, val);
    if (reply == NULL)
    {
        log_error("set_int_ex fails: %s", ctx->errstr);
        // handle error
        return;
    }
    if (reply->type == REDIS_REPLY_STATUS) {
        log_debugv("set_int_ex %s %d %s", key, val, reply->str);
    }
    else {
        log_warn("set_int_ex: unexpected reply type: %d", reply->type);
    }

    freeReplyObject(reply);
}

void set_str_ex_nx(const char *key, const char *val, int timeout)
{
    redisReply *reply;
    reply = redisCommand(ctx, "SET %s %s EX %d NX", key, val, timeout);
    if (reply == NULL)
    {
        log_error("set_str_ex_nx fails: %s", ctx->errstr);
        // handle error
        return;
    }
    if (reply->type == REDIS_REPLY_STATUS) {
        log_debugv("set_str_ex_nx %s %d %s", key, val, reply->str);
    }
    else if (reply->type == REDIS_REPLY_NIL) {
        log_debugv("set_str_ex_nx: %s exists", key);
    }
    else {
        log_warn("set_str_ex_nx: unexpected reply type: %d", reply->type);
    }

    freeReplyObject(reply);
}

void set_int_ex_nx(const char *key, int val, int timeout)
{
    redisReply *reply;
    reply = redisCommand(ctx, "SET %s %d EX %d NX", key, val, timeout);
    if (reply == NULL)
    {
        log_error("set_int_ex_nx fails: %s", ctx->errstr);
        // handle error
        return;
    }
    if (reply->type == REDIS_REPLY_STATUS) {
        log_debugv("set_int_ex_nx %s %d %s", key, val, reply->str);
    }
    else if (reply->type == REDIS_REPLY_NIL) {
        log_debugv("set_int_ex_nx: %s exists", key);
    }
    else {
        log_warn("set_int_ex_nx: unexpected reply type: %d", reply->type);
    }

    freeReplyObject(reply);
}

int incr(const char *key)
{
    int val = 0;

    redisReply *reply;
    reply = redisCommand(ctx, "INCR %s", key);
    if (reply == NULL)
    {
        log_error("incr fails: %s", ctx->errstr);
        // handle error
        return 0;
    }
    if (reply->type == REDIS_REPLY_INTEGER) {
        val = reply->integer;
        log_debugv("incr %s %d", key, val);
    }
    else {
        log_warn("incr: unexpected reply type: %d", reply->type);
    }

    freeReplyObject(reply);
    return val;
}

void expire(const char *key, int timeout)
{
    redisReply *reply;
    reply = redisCommand(ctx, "EXPIRE %s %d", key, timeout);
    if (reply == NULL)
    {
        log_error("expire fails: %s", ctx->errstr);
        // handle error
        return;
    }
    if (reply->type == REDIS_REPLY_INTEGER) {
        log_debugv("expire: %s %d", key, reply->integer);
    }
    else {
        log_warn("expire: unexpected reply type: %d", reply->type);
    }

    freeReplyObject(reply);
}

int keys_num(const char *pattern)
{
    int i;
    int num = 0;
    redisReply *reply;
    reply = redisCommand(ctx, "KEYS %s", pattern);
    if (reply == NULL)
    {
        log_error("keys fails: %s", ctx->errstr);
        // handle error
        return 0;
    }
    if (reply->type == REDIS_REPLY_ARRAY) {
        for (i = 0; i < reply->elements; i++) {
            log_debugv("%d) %s", i, reply->element[i]->str);
        }
        num = reply->elements;
        log_debugv("keys num: %s %d", pattern, num);
    }
    else {
        log_warn("keys: unexpected reply type: %d", reply->type);
    }

    freeReplyObject(reply);
    return num;
}

void keys(const char *pattern)
{
    int i;
    redisReply *reply;
    reply = redisCommand(ctx, "KEYS %s", pattern);
    if (reply == NULL)
    {
        log_error("keys fails: %s", ctx->errstr);
        // handle error
        return;
    }
    if (reply->type == REDIS_REPLY_ARRAY) {
        for (i = 0; i < reply->elements; i++) {
            log_debugv("%d) %s", i, reply->element[i]->str);
        }
    }
    else {
        log_warn("keys: unexpected reply type: %d", reply->type);
    }

    freeReplyObject(reply);
}

void del_key(const char *key)
{
    int i;
    redisReply *reply;
    reply = redisCommand(ctx, "DEL %s", key);
    if (reply == NULL)
    {
        log_error("del_key fails: %s", ctx->errstr);
        // handle error
        return;
    }
    if (reply->type == REDIS_REPLY_INTEGER) {
        log_debugv("del_key: %s %d", key, reply->integer);
    }
    else {
        log_warn("del_key: unexpected reply type: %d", reply->type);
    }

    freeReplyObject(reply);
}

void flushall()
{
    redisReply *reply;
    reply = redisCommand(ctx, "FLUSHALL");
    if (reply == NULL)
    {
        log_error("flushall fails: %s", ctx->errstr);
        // handle error
        return;
    }
    freeReplyObject(reply);
}

// get all the keys matching a certain pattern
int scan_match(const char *pattern, char keys[][64], int max_size)
{
    int i, j;
    int count = 0;
    int cursor = 0;

    do {
        redisReply *reply;
        reply = redisCommand(ctx, "SCAN %d MATCH %s", cursor, pattern);
        if (reply == NULL) 
        {
            log_error("scan_match fails: %s", ctx->errstr);
            // handle error
            return 0;
        }
        //if (reply->type == REDIS_REPLY_NIL) {
        //    log_debugv("scan_match: key not found: %s", pattern);
        //}
        if (reply->type == REDIS_REPLY_ARRAY) {
            log_debugv("scan_match: %s", pattern);
            for (i = 0; i < reply->elements; i++) {
                if (reply->element[i]->type == REDIS_REPLY_STRING) {
                    log_debugv("%u) %s", i+1, reply->element[i]->str);
                }
                else if (reply->element[i]->type == REDIS_REPLY_ARRAY) {
                    for (j = 0; j < reply->element[i]->elements; j++) {
                        if (reply->element[i]->element[j]->type == REDIS_REPLY_STRING) {
                            log_debugv("%u) %u) %s", i+1, j+1, reply->element[i]->element[j]->str);
                            if (count >= max_size) {
                                log_warn("scan_match: exceeds max size of %d", max_size);
                                return max_size;
                            }
                            keys[count][0] = 0;
                            strncat(keys[count], reply->element[i]->element[j]->str, 64);
                            count++;
                        }
                        else
                            log_warn("scan_match: unexpected reply type: %d", 
                                    reply->element[i]->element[j]->type);
                    }
                }
                else
                    log_warn("scan_match: unexpected reply type: %d", 
                            reply->element[i]->type);
            }
        }
        else {
            log_warn("scan_match: unexpected reply type: %d", reply->type);
        }
        cursor = strtol(reply->element[0]->str, NULL, 10);

        freeReplyObject(reply);
    } 
    while (cursor != 0);
    log_debugv("done");

    return count;
}



