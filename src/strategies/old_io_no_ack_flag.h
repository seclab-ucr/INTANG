
struct mypacket;

int x33_setup();
int x33_teardown();
int x33_process_syn(struct mypacket *packet);
int x33_process_synack(struct mypacket *packet);
int x33_process_request(struct mypacket *packet);
int x33_failed();

