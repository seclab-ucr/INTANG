
struct mypacket;

int x32_setup();
int x32_teardown();
int x32_process_syn(struct mypacket *packet);
int x32_process_synack(struct mypacket *packet);
int x32_process_request(struct mypacket *packet);
int x32_failed();

