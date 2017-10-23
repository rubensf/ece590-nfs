#include <libssh/libssh.h>
#include <libssh/sftp.h>

#include <stdio.h>

#include "sshlib.h"

ssh_session make_ssh_connection(const char* user, const char* host) {
  ssh_session ssh_sess = ssh_new();

  int verbosity = SSH_LOG_NOLOG;
  int nohostkeycheck = 0;

  ssh_sess = ssh_new();
  if (ssh_sess == NULL) {
    fprintf(stderr, "Error connecting to %s@%s: %s\n",
            user, host, ssh_get_error(ssh_sess));
    return NULL;
  }

  ssh_options_set(ssh_sess, SSH_OPTIONS_USER, user);
  ssh_options_set(ssh_sess, SSH_OPTIONS_HOST, host);
  ssh_options_set(ssh_sess, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);

  if (ssh_connect(ssh_sess) != SSH_OK) {
    fprintf(stderr, "Error connecting to %s@%s: %s\n",
            user, host, ssh_get_error(ssh_sess));
    return NULL;
  }

  if (ssh_is_server_known(ssh_sess) != SSH_SERVER_KNOWN_OK) {
    fprintf(stderr, "Error! Make sure to add your SSH key to the server beforehand.\n");
    return NULL;
  }

  if (ssh_userauth_publickey_auto(ssh_sess, NULL, NULL) != SSH_AUTH_SUCCESS) {
    fprintf(stderr, "Error! Could not authenticate.\n");
    return NULL;
  }

  return ssh_sess;
}

ssh_channel make_ssh_channel(ssh_session ssh_sess) {
  ssh_channel chann = ssh_channel_new(ssh_sess);
  if (chann == NULL) {
    fprintf(stderr, "Error! Could not make ssh channel.\n");
    return NULL;
  }
  if (ssh_channel_open_session(chann) != SSH_OK) {
    fprintf(stderr, "Error! Could not start ssh channel.\n");
    return NULL;
  }
  if (ssh_channel_request_shell(chann) != SSH_OK) {
    fprintf(stderr, "Error! Could not start ssh shell.\n");
    return NULL;
  }

  return chann;
}

sftp_session make_sftp_session(ssh_session ssh_sess) {
  sftp_session sftp_sess = sftp_new(ssh_sess);
  if (sftp_sess == NULL) {
    fprintf(stderr, "Error! Could not make sftp session.\n");
    return NULL;
  }
  if (sftp_init(sftp_sess) != SSH_OK) {
    fprintf(stderr, "Error! Could not init sftp session.\n");
    return NULL;
  }

  return sftp_sess;
}
