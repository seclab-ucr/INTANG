
struct mypacket;

int x28_setup();
int x28_teardown();
int x28_process_syn(struct mypacket *packet);
int x28_process_synack(struct mypacket *packet);
int x28_process_request(struct mypacket *packet);
int x28_failed();

