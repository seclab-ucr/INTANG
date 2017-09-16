
struct mypacket;

int x16_setup();
int x16_teardown();
int x16_process_synack(struct mypacket *packet);
int x16_process_request(struct mypacket *packet);
int x16_failed();

