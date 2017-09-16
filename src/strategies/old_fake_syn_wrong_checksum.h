
struct mypacket;

int x27_setup();
int x27_teardown();
int x27_process_syn(struct mypacket *packet);
int x27_process_synack(struct mypacket *packet);
int x27_process_request(struct mypacket *packet);
int x27_failed();

