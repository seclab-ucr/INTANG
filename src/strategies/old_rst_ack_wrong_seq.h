
struct mypacket;

int x39_setup();
int x39_teardown();
int x39_process_syn(struct mypacket *packet);
int x39_process_synack(struct mypacket *packet);
int x39_process_request(struct mypacket *packet);
int x39_failed();

