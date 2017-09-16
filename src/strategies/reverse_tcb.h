
struct mypacket;

int x17_setup();
int x17_teardown();
int x17_process_syn(struct mypacket *packet);
int x17_process_synack(struct mypacket *packet);
int x17_process_request(struct mypacket *packet);
int x17_failed();

