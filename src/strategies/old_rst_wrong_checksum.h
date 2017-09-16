
struct mypacket;

int x35_setup();
int x35_teardown();
int x35_process_syn(struct mypacket *packet);
int x35_process_synack(struct mypacket *packet);
int x35_process_request(struct mypacket *packet);
int x35_failed();

