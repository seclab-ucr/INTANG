
#ifndef __DBHELPER_H__
#define __DBHELPER_H__


#define DB_ENTRY_NOT_FOUND -1
#define DB_ENTRY_NEW       0
#define DB_ENTRY_EXISTS    1


struct entry {
    char key[16];
    int value;
};

#define KEY_SIZE 16 // the max length of an IP is 16
#define MAX_ENTRY_NUM 100000 // can store at most 100,000 entries

typedef struct _db_struct {
    int entry_num;
    struct entry *all_entries;
} db_struct;


db_struct db[10];

typedef int db_handle;

db_handle* open_db(const char *db_name);

void close_db(db_handle* handle);

int db_get(db_handle *handle, const char *key);

int db_set(db_handle *handle, const char *key, int value);

void dump_all_entries(db_handle *handle);


#endif

