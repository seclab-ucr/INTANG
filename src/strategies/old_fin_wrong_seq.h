
struct mypacket;

int x42_setup();
int x42_teardown();
int x42_process_syn(struct mypacket *packet);
int x42_process_synack(struct mypacket *packet);
int x42_process_request(struct mypacket *packet);
int x42_failed();

