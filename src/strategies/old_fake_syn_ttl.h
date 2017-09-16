
struct mypacket;

int x26_setup();
int x26_teardown();
int x26_process_syn(struct mypacket *packet);
int x26_process_synack(struct mypacket *packet);
int x26_process_request(struct mypacket *packet);
int x26_failed();

