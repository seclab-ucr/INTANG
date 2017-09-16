
struct mypacket;

int x23_setup();
int x23_teardown();
int x23_process_syn(struct mypacket *packet);
int x23_process_synack(struct mypacket *packet);
int x23_process_request(struct mypacket *packet);
int x23_failed();

