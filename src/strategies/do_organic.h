
struct mypacket;

int x20_setup();
int x20_teardown();
int x20_process_synack(struct mypacket *packet);
int x20_process_request(struct mypacket *packet);
int x20_failed();

