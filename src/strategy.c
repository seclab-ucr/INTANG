

#include "strategy.h"

#include <stdio.h>
#include <stdlib.h>

#include "logging.h"
#include "memcache.h"
#include "helper.h"
#include "redis.h"

#include "dummy.h"
#include "rst_small_ttl.h"
#include "rst_wrong_ack.h"
#include "rst_md5_opt.h"
#include "rst_wrong_checksum.h"
#include "rst_small_ttl_and_wrong_ack.h"
#include "rst_super.h"
#include "syn_reset.h"
#include "do_wrong_checksum.h"
#include "do_md5_opt.h"
#include "do_super.h"
#include "multiple_syn.h"
#include "rst_desync.h"
#include "mixed_strategy.h"
#include "mixed_do_ms.h"
#include "mixed_ms_rd.h"
#include "mixed_do_rd.h"
#include "reverse_tcb.h"
#include "test_probing_ttl.h"
#include "rst_organic.h"
#include "do_organic.h"
#include "do_organic_wrong_checksum.h"
#include "do_super_wrong_checksum.h"
#include "multiple_syn_wrong_checksum.h"
#include "reverse_tcb_wrong_checksum.h"
#include "rst_organic_wrong_checksum.h"
#include "old_fake_syn_ttl.h"
#include "old_fake_syn_wrong_checksum.h"
#include "old_ooo_ip_fragment.h"
#include "old_ooo_tcp_fragment.h"
#include "old_io_ttl.h"
#include "old_io_wrong_ack.h"
#include "old_io_wrong_checksum.h"
#include "old_io_no_ack_flag.h"
#include "old_rst_ttl.h"
#include "old_rst_wrong_checksum.h"
#include "old_rst_wrong_seq.h"
#include "old_rst_ack_ttl.h"
#include "old_rst_ack_wrong_checksum.h"
#include "old_rst_ack_wrong_seq.h"
#include "old_fin_ttl.h"
#include "old_fin_wrong_checksum.h"
#include "old_fin_wrong_seq.h"
#include "old_rst_ttl_max.h"
#include "old_io_ttl_max.h"


const struct strategy g_strats[] = {
    {
        .id                 = 0,
        .name               = "dummy",
        .setup              = x0_setup,
        .teardown           = x0_teardown,
    },
    {
        .id                 = 1,
        .name               = "rst_small_ttl",
        .setup              = x1_setup,
        .teardown           = x1_teardown,
        .process_syn        = x1_process_syn,
        .process_synack     = x1_process_synack,
        .process_request    = x1_process_request,
    },
    {
        .id                 = 2,
        .name               = "rst_wrong_ack",
        .setup              = x2_setup,
        .teardown           = x2_teardown,
        .process_synack     = x2_process_synack,
    },
    {
        .id                 = 3,
        .name               = "rst_md5_opt",
        .setup              = x3_setup,
        .teardown           = x3_teardown,
        .process_synack     = x3_process_synack,
        .process_request    = x3_process_request,
    },
    {
        .id                 = 4,
        .name               = "rst_wrong_checksum",
        .setup              = x4_setup,
        .teardown           = x4_teardown,
        .process_synack     = x4_process_synack,
        .process_request    = x4_process_request,
    },
    {
        .id                 = 5,
        .name               = "rst_small_ttl_and_wrong_ack",
        .setup              = x5_setup,
        .teardown           = x5_teardown,
        .process_syn        = x5_process_syn,
        .process_synack     = x5_process_synack,
        .process_request    = x5_process_request,
    },
    {
        .id                 = 6,
        .name               = "rst_super",
        .setup              = x6_setup,
        .teardown           = x6_teardown,
        //.process_syn        = x6_process_syn,
        //.process_synack     = x6_process_synack,
        .process_request    = x6_process_request,
    },
    {
        .id                 = 7,
        .name               = "syn_reset",
        .setup              = x7_setup,
        .teardown           = x7_teardown,
        .process_synack     = x7_process_synack,
    },
    {
        .id                 = 8,
        .name               = "data_overlapping_wrong_checksum",
        .setup              = x8_setup,
        .teardown           = x8_teardown,
        .process_request    = x8_process_request,
    },
    {
        .id                 = 9,
        .name               = "data_overlapping_md5_opt",
        .setup              = x9_setup,
        .teardown           = x9_teardown,
        .process_request    = x9_process_request,
    },
    {
        .id                 = 10,
        .name               = "data_overlapping_combined",
        .setup              = x10_setup,
        .teardown           = x10_teardown,
        //.process_syn        = x10_process_syn,
        //.process_synack     = x10_process_synack,
        .process_request    = x10_process_request,
    },
    {
        .id                 = 11,
        .name               = "multiple_syn",
        .setup              = x11_setup,
        .teardown           = x11_teardown,
        .process_syn        = x11_process_syn,
        .process_request    = x11_process_request,
    },
    {
        .id                 = 12,
        .name               = "rst_desync",
        .setup              = x12_setup,
        .teardown           = x12_teardown,
        .process_synack     = x12_process_synack,
    },
    {
        .id                 = 13,
        .name               = "mixed_strategy",
        .setup              = x13_setup,
        .teardown           = x13_teardown,
        .process_syn        = x13_process_syn,
        .process_synack     = x13_process_synack,
        .process_request    = x13_process_request,
    },
    {
        .id                 = 14,
        .name               = "mixed_do_ms",
        .setup              = x14_setup,
        .teardown           = x14_teardown,
        .process_syn        = x14_process_syn,
        .process_synack     = x14_process_synack,
        .process_request    = x14_process_request,
    },
    {
        .id                 = 15,
        .name               = "mixed_ms_rd",
        .setup              = x15_setup,
        .teardown           = x15_teardown,
        .process_syn        = x15_process_syn,
        .process_synack     = x15_process_synack,
    },
    {
        .id                 = 16,
        .name               = "mixed_do_rd",
        .setup              = x16_setup,
        .teardown           = x16_teardown,
        .process_synack     = x16_process_synack,
        .process_request    = x16_process_request,
    },
    {
        .id                 = 17,
        .name               = "reverse_tcb",
        .setup              = x17_setup,
        .teardown           = x17_teardown,
        .process_syn        = x17_process_syn,
        .process_request    = x17_process_request,
    },
    {
        .id                 = 18,
        .name               = "test_probing_ttl",
        .setup              = x18_setup,
        .teardown           = x18_teardown,
        .process_syn        = x18_process_syn,
        .process_synack     = x18_process_synack,
        .process_request    = x18_process_request,
    },
    {
        .id                 = 19,
        .name               = "rst_organic",
        .setup              = x19_setup,
        .teardown           = x19_teardown,
        .process_syn        = x19_process_syn,
        .process_synack     = x19_process_synack,
        .process_request    = x19_process_request,
    },
    {
        .id                 = 20,
        .name               = "data_overlapping_organic",
        .setup              = x20_setup,
        .teardown           = x20_teardown,
        .process_request    = x20_process_request,
    },
    {
        .id                 = 21,
        .name               = "data_overlapping_organic_wrong_checksum",
        .setup              = x21_setup,
        .teardown           = x21_teardown,
        .process_request    = x21_process_request,
    },
    {
        .id                 = 22,
        .name               = "data_overlapping_combined_wrong_checksum",
        .setup              = x22_setup,
        .teardown           = x22_teardown,
        .process_synack     = x22_process_synack,
        .process_request    = x22_process_request,
    },
    {
        .id                 = 23,
        .name               = "multiple_syn_wrong_checksum",
        .setup              = x23_setup,
        .teardown           = x23_teardown,
        .process_syn        = x23_process_syn,
        .process_request    = x23_process_request,
    },
    {
        .id                 = 24,
        .name               = "reverse_tcb_wrong_checksum", 
        .setup              = x24_setup,
        .teardown           = x24_teardown,
        .process_syn        = x24_process_syn,
        .process_request    = x24_process_request,
    },
    {
        .id                 = 25,
        .name               = "rst_organic_wrong_checksum", 
        .setup              = x25_setup,
        .teardown           = x25_teardown,
        .process_syn        = x25_process_syn,
        .process_request    = x25_process_request,
    },
    {
        .id                 = 26,
        .name               = "old_fake_syn_ttl", 
        .setup              = x26_setup,
        .teardown           = x26_teardown,
        .process_syn        = x26_process_syn,
        //.process_request    = x26_process_request,
    },
    {
        .id                 = 27,
        .name               = "old_fake_syn_wrong_checksum", 
        .setup              = x27_setup,
        .teardown           = x27_teardown,
        .process_syn        = x27_process_syn,
        //.process_request    = x27_process_request,
    },
    {
        .id                 = 28,
        .name               = "old_ooo_ip_fragment", 
        .setup              = x28_setup,
        .teardown           = x28_teardown,
        //.process_syn        = x28_process_syn,
        .process_request    = x28_process_request,
    },
    {
        .id                 = 29,
        .name               = "old_ooo_tcp_fragment", 
        .setup              = x29_setup,
        .teardown           = x29_teardown,
        //.process_syn        = x29_process_syn,
        .process_request    = x29_process_request,
    },
    {
        .id                 = 30,
        .name               = "old_io_ttl", 
        .setup              = x30_setup,
        .teardown           = x30_teardown,
        //.process_syn        = x30_process_syn,
        .process_request    = x30_process_request,
    },
    {
        .id                 = 31,
        .name               = "old_io_wrong_ack", 
        .setup              = x31_setup,
        .teardown           = x31_teardown,
        //.process_syn        = x31_process_syn,
        .process_request    = x31_process_request,
    },
    {
        .id                 = 32,
        .name               = "old_io_wrong_checksum", 
        .setup              = x32_setup,
        .teardown           = x32_teardown,
        //.process_syn        = x32_process_syn,
        .process_request    = x32_process_request,
    },
    {
        .id                 = 33,
        .name               = "old_io_no_ack_flag", 
        .setup              = x33_setup,
        .teardown           = x33_teardown,
        //.process_syn        = x33_process_syn,
        .process_request    = x33_process_request,
    },
    {
        .id                 = 34,
        .name               = "old_rst_ttl", 
        .setup              = x34_setup,
        .teardown           = x34_teardown,
        //.process_syn        = x34_process_syn,
        .process_synack     = x34_process_synack,
        //.process_request    = x34_process_request,
    },
    {
        .id                 = 35,
        .name               = "old_rst_wrong_checksum", 
        .setup              = x35_setup,
        .teardown           = x35_teardown,
        //.process_syn        = x35_process_syn,
        .process_synack     = x35_process_synack,
        //.process_request    = x35_process_request,
    },
    {
        .id                 = 36,
        .name               = "old_rst_wrong_seq", 
        .setup              = x36_setup,
        .teardown           = x36_teardown,
        //.process_syn        = x36_process_syn,
        .process_synack     = x36_process_synack,
        //.process_request    = x36_process_request,
    },
    {
        .id                 = 37,
        .name               = "old_rst_ack_ttl", 
        .setup              = x37_setup,
        .teardown           = x37_teardown,
        //.process_syn        = x37_process_syn,
        .process_synack     = x37_process_synack,
        //.process_request    = x37_process_request,
    },
    {
        .id                 = 38,
        .name               = "old_rst_ack_wrong_checksum", 
        .setup              = x38_setup,
        .teardown           = x38_teardown,
        //.process_syn        = x38_process_syn,
        .process_synack     = x38_process_synack,
        //.process_request    = x38_process_request,
    },
    {
        .id                 = 39,
        .name               = "old_rst_ack_wrong_seq", 
        .setup              = x39_setup,
        .teardown           = x39_teardown,
        //.process_syn        = x39_process_syn,
        .process_synack     = x39_process_synack,
        //.process_request    = x39_process_request,
    },
    {
        .id                 = 40,
        .name               = "old_fin_ttl", 
        .setup              = x40_setup,
        .teardown           = x40_teardown,
        //.process_syn        = x40_process_syn,
        .process_synack     = x40_process_synack,
        //.process_request    = x40_process_request,
    },
    {
        .id                 = 41,
        .name               = "old_fin_wrong_checksum", 
        .setup              = x41_setup,
        .teardown           = x41_teardown,
        //.process_syn        = x41_process_syn,
        .process_synack     = x41_process_synack,
        //.process_request    = x41_process_request,
    },
    {
        .id                 = 42,
        .name               = "old_fin_wrong_seq", 
        .setup              = x42_setup,
        .teardown           = x42_teardown,
        //.process_syn        = x42_process_syn,
        .process_synack     = x42_process_synack,
        //.process_request    = x42_process_request,
    },
    {
        .id                 = 43,
        .name               = "old_rst_ttl_max", 
        .setup              = x43_setup,
        .teardown           = x43_teardown,
        //.process_syn        = x43_process_syn,
        //.process_synack     = x43_process_synack,
        .process_request    = x43_process_request,
    },
    {
        .id                 = 44,
        .name               = "old_io_ttl_max", 
        .setup              = x44_setup,
        .teardown           = x44_teardown,
        //.process_syn        = x44_process_syn,
        //.process_synack     = x44_process_synack,
        .process_request    = x44_process_request,
    },
};

int g_strat_weights[] = {5, 10, 10, 10, 10, 10, 100, 0, 10, 10, 100, 100, 20, 10, 10, 10, 10, 100, 0, 20, 10, 10, 10, 10, 10, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ,0, 0, 0};
int g_strat_num = sizeof(g_strat_weights)/sizeof(g_strat_weights[0]);


int choose_strategy_randomly()
{
    int cnt = sizeof(g_strats)/sizeof(g_strats[0]);
    //log_info("cnt: %d", cnt);
    return rand() % cnt;
}

int choose_strategy_by_weight()
{
    int i;
    int tot_weights = 0;
    //log_info("cnt: %d", g_strat_num);
    for (i=0; i<g_strat_num; i++) {
        tot_weights += g_strat_weights[i];
    }
    int r = rand() % tot_weights;
    int a_weights = 0;
    for (i=0; i<g_strat_num; i++) {
        a_weights += g_strat_weights[i];
        if (a_weights > r)
            return i;
    }
    return 0;
}

int choose_strategy_by_historical_result(unsigned int daddr) {
    int i;
    struct historical_result *hist_res = get_hist_res(daddr);
    if (hist_res == NULL) 
        return choose_strategy_by_weight();

    double best_succ_rate = 0;
    int best_sid = 0;
    int total_count = 0;
    for (i = 0; i < g_strat_num; i++) {
        total_count += hist_res[i].succ + hist_res[i].fail1 + hist_res[i].fail2;
        double succ_rate = (double)hist_res[i].succ / (hist_res[i].succ + hist_res[i].fail1 + hist_res[i].fail2);
        if (succ_rate > best_succ_rate) {
            best_sid = i;
            best_succ_rate = succ_rate;
        }
    }
    if (total_count < 10) {
        // cold-start
        return choose_strategy_by_weight();
    }

    char dip[16];
    log_debug("Using strategy %d for %s. Historical succ rate: %f.\n", best_sid, ip2str(daddr, dip), best_succ_rate);

    return best_sid;
}

int choose_strategy()
{
    int sid;
    sid = choose_strategy_by_weight();
    //sid = choose_strategy_randomly();
    return sid;
}


void dump_strat_weights() {
    // debug
    for (int i = 0; i < g_strat_num; i++) {
        log_debug("%d. %s: %d", i, g_strats[i].name, g_strat_weights[i]);
    }
}


