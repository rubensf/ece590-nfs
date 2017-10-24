#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <libsocket/libinetsocket.h>

int doThing(int cfd) {
  printf("hello from child!");
  char bytes[300];
  read(cfd, bytes, 300);
  printf("%s\n", bytes);
  return 0;
}

int main(void) {
  int sfd, bytes, ret;
  char src_host[128], src_port[7];

  src_host[127] = 0;
  src_port[6] = 0;

  sfd = create_inet_server_socket(
      "::", "1111", LIBSOCKET_TCP, LIBSOCKET_IPv6, 0);
  if (sfd == -1) {
    perror("Couldn't create server");
    exit(1);
  }
  printf("Socket up and running\n");

  while (1) {
    int cfd = accept_inet_stream_socket(
        sfd, src_host, 127, src_port, 6, LIBSOCKET_NUMERIC,0);
    if (cfd == -1) {
      perror("Couldn't accept connection");
      exit(1);
    }

    printf("Connection from %s port %s.\n", src_host, src_port);
    if (fork() == 0) {
      doThing(cfd);
      return 0;
    }
  }

  if (destroy_inet_socket(sfd) < 0) {
    perror(0);
    exit(1);
  }

  return 0;
}
