
struct mypacket;

int x11_setup();
int x11_teardown();
int x11_process_syn(struct mypacket *packet);
int x11_process_synack(struct mypacket *packet);
int x11_process_request(struct mypacket *packet);
int x11_failed();

