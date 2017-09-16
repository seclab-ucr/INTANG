
struct mypacket;

int x14_setup();
int x14_teardown();
int x14_process_syn(struct mypacket *packet);
int x14_process_synack(struct mypacket *packet);
int x14_process_request(struct mypacket *packet);
int x14_failed();

