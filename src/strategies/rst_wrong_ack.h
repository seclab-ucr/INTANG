
struct mypacket;

int x2_setup();
int x2_teardown();
int x2_process_synack(struct mypacket *packet);
int x2_process_request(struct mypacket *packet);
int x2_failed();

