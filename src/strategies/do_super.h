
struct mypacket;

int x10_setup();
int x10_teardown();
int x10_process_synack(struct mypacket *packet);
int x10_process_request(struct mypacket *packet);
int x10_failed();

