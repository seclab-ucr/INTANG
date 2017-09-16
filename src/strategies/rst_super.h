
struct mypacket;

int x6_setup();
int x6_teardown();
int x6_process_syn(struct mypacket *packet);
int x6_process_synack(struct mypacket *packet);
int x6_process_request(struct mypacket *packet);
int x6_failed();

