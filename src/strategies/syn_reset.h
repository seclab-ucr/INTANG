
struct mypacket;

int x7_setup();
int x7_teardown();
int x7_process_synack(struct mypacket *packet);
int x7_process_request(struct mypacket *packet);
int x7_failed();

