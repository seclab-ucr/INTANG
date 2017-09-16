
struct mypacket;

int x37_setup();
int x37_teardown();
int x37_process_syn(struct mypacket *packet);
int x37_process_synack(struct mypacket *packet);
int x37_process_request(struct mypacket *packet);
int x37_failed();

