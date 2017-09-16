
struct mypacket;

int x24_setup();
int x24_teardown();
int x24_process_syn(struct mypacket *packet);
int x24_process_synack(struct mypacket *packet);
int x24_process_request(struct mypacket *packet);
int x24_failed();

