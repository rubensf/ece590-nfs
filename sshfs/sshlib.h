#include <libssh/libssh.h>
#include <libssh/sftp.h>

#ifndef SSHLIB_H_
#define SSHLIB_H_

ssh_session make_ssh_connection(const char* user, const char* host);
ssh_channel make_ssh_channel(ssh_session ssh_sess);
sftp_session make_sftp_session(ssh_session ssh_sess);

#endif /* SSHLIB_H_ */
