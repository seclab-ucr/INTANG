
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <sys/stat.h>

#include "globals.h"


static FILE *log_file;

extern int opt_logging_to_file;

extern int opt_logging_level;


int init_log()
{
    if (opt_logging_to_file) {
        log_file = fopen(LOG_FILE, "w");
        if (log_file == NULL) {
            fprintf(stderr, "Failed to open or create log file %s\n", LOG_FILE);
            return -1;
        }
        chmod(LOG_FILE, 0644);
        setbuf(log_file, NULL);
    }
    return 0;
}

int fin_log()
{
    if (opt_logging_to_file && log_file != NULL) {
        fclose(log_file);
    }
    return 0;
}

const char LEVEL_STR[][10] = {
    "ERROR", 
    "WARNING",
    "INFO",
    "DEBUG",
    "DEBUGV",
};

void log_func(int level, const char *fmt, ...)
{
    va_list ap;
    char buffer[1024];
    char time_str[20];
    time_t rawtime;
    struct tm * timeinfo;
    struct timespec ts;
    double time_ts;

    if (level > opt_logging_level)
        return;

    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(time_str, 20, "%Y-%m-%d %H:%M:%S", timeinfo);

    // a more acurate timestamp 
    clock_gettime(CLOCK_REALTIME, &ts);
    time_ts = ts.tv_sec + ts.tv_nsec / 1000000000.0;

    va_start(ap, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, ap);
    if (opt_logging_to_file && log_file != NULL) {
        fprintf(log_file, "%lf [%s] %s\n", time_ts, LEVEL_STR[level], buffer);
    } else {
        fprintf(stdout, "%lf [%s] %s\n", time_ts, LEVEL_STR[level], buffer);
    }
    va_end(ap);
}



