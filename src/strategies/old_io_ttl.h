
struct mypacket;

int x30_setup();
int x30_teardown();
int x30_process_syn(struct mypacket *packet);
int x30_process_synack(struct mypacket *packet);
int x30_process_request(struct mypacket *packet);
int x30_failed();

