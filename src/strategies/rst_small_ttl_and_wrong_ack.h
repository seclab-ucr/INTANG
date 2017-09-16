
struct mypacket;

int x5_setup();
int x5_teardown();
int x5_process_syn(struct mypacket *packet);
int x5_process_synack(struct mypacket *packet);
int x5_process_request(struct mypacket *packet);
int x5_failed();

