
struct mypacket;

int x19_setup();
int x19_teardown();
int x19_process_syn(struct mypacket *packet);
int x19_process_synack(struct mypacket *packet);
int x19_process_request(struct mypacket *packet);
int x19_failed();

