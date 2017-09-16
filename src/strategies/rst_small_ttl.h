
struct mypacket;

int x1_setup();
int x1_teardown();
int x1_process_syn(struct mypacket *packet);
int x1_process_synack(struct mypacket *packet);
int x1_process_request(struct mypacket *packet);
int x1_failed();

