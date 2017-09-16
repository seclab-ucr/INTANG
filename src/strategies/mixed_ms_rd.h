
struct mypacket;

int x15_setup();
int x15_teardown();
int x15_process_syn(struct mypacket *packet);
int x15_process_synack(struct mypacket *packet);
int x15_failed();

