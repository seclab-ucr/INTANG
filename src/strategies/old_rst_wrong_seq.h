
struct mypacket;

int x36_setup();
int x36_teardown();
int x36_process_syn(struct mypacket *packet);
int x36_process_synack(struct mypacket *packet);
int x36_process_request(struct mypacket *packet);
int x36_failed();

