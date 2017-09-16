
struct mypacket;

int x40_setup();
int x40_teardown();
int x40_process_syn(struct mypacket *packet);
int x40_process_synack(struct mypacket *packet);
int x40_process_request(struct mypacket *packet);
int x40_failed();

