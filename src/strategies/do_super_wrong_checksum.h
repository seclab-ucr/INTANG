
struct mypacket;

int x22_setup();
int x22_teardown();
int x22_process_synack(struct mypacket *packet);
int x22_process_request(struct mypacket *packet);
int x22_failed();

