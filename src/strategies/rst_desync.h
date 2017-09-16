
struct mypacket;

int x12_setup();
int x12_teardown();
int x12_process_syn(struct mypacket *packet);
int x12_process_synack(struct mypacket *packet);
int x12_process_request(struct mypacket *packet);
int x12_failed();

