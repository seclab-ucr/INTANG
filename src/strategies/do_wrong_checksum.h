
struct mypacket;

int x8_setup();
int x8_teardown();
int x8_process_synack(struct mypacket *packet);
int x8_process_request(struct mypacket *packet);
int x8_failed();

