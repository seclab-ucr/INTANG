
struct mypacket;

int x21_setup();
int x21_teardown();
int x21_process_synack(struct mypacket *packet);
int x21_process_request(struct mypacket *packet);
int x21_failed();

