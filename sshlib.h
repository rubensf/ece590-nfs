#include <libssh/libssh.h>

ssh_session make_ssh_connection(const char* user, const char* host);
ssh_channel make_ssh_channel(ssh_session ssh_sess);
