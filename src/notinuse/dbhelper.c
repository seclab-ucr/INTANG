/*
 * This file is not used.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "globals.h"
#include "dbhelper.h"
#include "logging.h"

#define DB_FILE "hosts"

static struct entry *all_entries;
static int entry_num;


db_handle* db_open(const char *db_name)
{
    FILE *db_file;
    char buffer[100];
    char *tok;

    if (all_entries)
        free(all_entries);
    all_entries = (struct entry*)calloc(MAX_ENTRY_NUM, sizeof(struct entry));

    db_file = fopen(DB_FILE, "r");
    if (db_file == NULL) {
        log_error("db not exists.");
        return NULL;
    }

    while (fgets(buffer, 100, db_file) != NULL) {
        if (strlen(buffer) == 0 || buffer[0] == ' ' || buffer[0] == '\n')
            continue;
        tok = strtok(buffer, "\t");
        strncpy(all_entries[entry_num].key, tok, KEY_SIZE);
        tok = strtok(NULL, " ");
        all_entries[entry_num].value = atoi(tok);
        entry_num++;
    }

    fclose(db_file);
    return NULL;
}

int db_get(db_handle *handle, const char *key)
{
    int i;
    for (i=0; i<entry_num; i++) {
        if (strcmp(all_entries[i].key, key) == 0) {
            return all_entries[i].value;
        }
    }
    return DB_ENTRY_NOT_FOUND;
}

int db_set(db_handle *handle, const char *key, int value) 
{
    int i;
    for (i=0; i<entry_num; i++) {
        if (strcmp(all_entries[i].key, key) == 0) {
            all_entries[i].value = value;
            return DB_ENTRY_EXISTS;
        }
    }
    strncpy(all_entries[entry_num].key, key, KEY_SIZE);
    all_entries[entry_num].value = value;
    entry_num++;
    return DB_ENTRY_NEW;
}


void db_close(db_handle *handle)
{
    FILE *db_file;
    
    if (!all_entries || entry_num == 0)
        return;

    db_file = fopen(DB_FILE, "w");

    int i;
    for (i=0; i<entry_num; i++) {
        fprintf(db_file, "%s\t%d\n", all_entries[i].key, all_entries[i].value);
    }

    fclose(db_file);
    free(all_entries);
}

void dump_all_entries(db_handle *handle)
{
    int i;
    log_debug("Total entries: %d", entry_num);
    for (i=0; i<entry_num; i++) {
        log_debug("%d. %s\t%d", (i+1), all_entries[i].key, all_entries[i].value);
    }
}

