
struct mypacket;

int x25_setup();
int x25_teardown();
int x25_process_syn(struct mypacket *packet);
int x25_process_synack(struct mypacket *packet);
int x25_process_request(struct mypacket *packet);
int x25_failed();

