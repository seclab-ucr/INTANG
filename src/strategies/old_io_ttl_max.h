
struct mypacket;

int x44_setup();
int x44_teardown();
int x44_process_syn(struct mypacket *packet);
int x44_process_synack(struct mypacket *packet);
int x44_process_request(struct mypacket *packet);
int x44_failed();

