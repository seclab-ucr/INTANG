
struct mypacket;

int x43_setup();
int x43_teardown();
int x43_process_syn(struct mypacket *packet);
int x43_process_synack(struct mypacket *packet);
int x43_process_request(struct mypacket *packet);
int x43_failed();

