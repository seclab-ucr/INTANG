
struct mypacket;

int x29_setup();
int x29_teardown();
int x29_process_syn(struct mypacket *packet);
int x29_process_synack(struct mypacket *packet);
int x29_process_request(struct mypacket *packet);
int x29_failed();

