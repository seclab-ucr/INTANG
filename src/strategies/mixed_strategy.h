
struct mypacket;

int x13_setup();
int x13_teardown();
int x13_process_syn(struct mypacket *packet);
int x13_process_synack(struct mypacket *packet);
int x13_process_request(struct mypacket *packet);
int x13_failed();

