
#ifndef __REDIS_H__
#define __REDIS_H__


void delete_redis_db();

int connect_to_redis();

int disconnect_from_redis();

void get_str(const char *key, char *val, size_t len);

int get_int(const char *key);

void set_str(const char *key, const char *val);

void set_int(const char *key, int val);

void set_str_ex(const char *key, const char *val, int timeout);

void set_int_ex(const char *key, int val, int timeout);

void set_str_ex_nx(const char *key, const char *val, int timeout);

void set_int_ex_nx(const char *key, int val, int timeout);

int incr(const char *key);

void expire(const char *key, int timeout);

void keys(const char *pattern);

int keys_num(const char *pattern);

void del_key(const char *key);

int scan_match(const char *pattern, char keys[][64], int max_size);


#endif



