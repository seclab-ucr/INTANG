
struct mypacket;

int x34_setup();
int x34_teardown();
int x34_process_syn(struct mypacket *packet);
int x34_process_synack(struct mypacket *packet);
int x34_process_request(struct mypacket *packet);
int x34_failed();

