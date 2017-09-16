
struct mypacket;

int x38_setup();
int x38_teardown();
int x38_process_syn(struct mypacket *packet);
int x38_process_synack(struct mypacket *packet);
int x38_process_request(struct mypacket *packet);
int x38_failed();

