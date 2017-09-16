
struct mypacket;

int x18_setup();
int x18_teardown();
int x18_process_syn(struct mypacket *packet);
int x18_process_synack(struct mypacket *packet);
int x18_process_request(struct mypacket *packet);
int x18_failed();

