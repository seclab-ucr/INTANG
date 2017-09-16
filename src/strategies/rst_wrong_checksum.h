
struct mypacket;

int x4_setup();
int x4_teardown();
int x4_process_synack(struct mypacket *packet);
int x4_process_request(struct mypacket *packet);
int x4_failed();

