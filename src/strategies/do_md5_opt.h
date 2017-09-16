
struct mypacket;

int x9_setup();
int x9_teardown();
int x9_process_synack(struct mypacket *packet);
int x9_process_request(struct mypacket *packet);
int x9_failed();

