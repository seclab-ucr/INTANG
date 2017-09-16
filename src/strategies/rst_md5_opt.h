
struct mypacket;

int x3_setup();
int x3_teardown();
int x3_process_synack(struct mypacket *packet);
int x3_process_request(struct mypacket *packet);
int x3_failed();

