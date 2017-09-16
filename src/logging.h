
#ifndef __LOGGING_H__
#define __LOGGING_H__


int init_log(void);
int fin_log(void);

void log_func(int level, const char *msg, ...);

#define log_error(args...) log_func(0, args)
#define log_warn(args...) log_func(1, args)
#define log_info(args...) log_func(2, args)
#define log_debug(args...) log_func(3, args)
#define log_debugv(args...) log_func(4, args)


#endif

