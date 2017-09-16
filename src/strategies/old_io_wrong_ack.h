
struct mypacket;

int x31_setup();
int x31_teardown();
int x31_process_syn(struct mypacket *packet);
int x31_process_synack(struct mypacket *packet);
int x31_process_request(struct mypacket *packet);
int x31_failed();

