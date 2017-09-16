
#ifndef __STRATEGY_H__
#define __STRATEGY_H__


struct mypacket;

struct strategy {
    int id;
    const char name[64];
    int (*setup)(void);
    int (*teardown)(void);
    int (*process_syn)(struct mypacket *packet);
    int (*process_synack)(struct mypacket *packet);
    int (*process_request)(struct mypacket *packet);
    int (*succeeded)(void);
    int (*failed)(void);
};

extern const struct strategy g_strats[];
extern int g_strat_weights[];
extern int g_strat_num;

int choose_strategy_by_historical_result(unsigned int daddr);
int choose_strategy();

// debug
void dump_strat_weights();


#endif

