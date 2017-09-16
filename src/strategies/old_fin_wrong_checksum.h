
struct mypacket;

int x41_setup();
int x41_teardown();
int x41_process_syn(struct mypacket *packet);
int x41_process_synack(struct mypacket *packet);
int x41_process_request(struct mypacket *packet);
int x41_failed();

