
struct mypacket;

int x0_setup();
int x0_teardown();
int x0_process_synack(struct mypacket *packet);
int x0_process_request(struct mypacket *packet);
int x0_failed();

