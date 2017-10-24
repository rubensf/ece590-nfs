#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libsocket/libinetsocket.h>

/*
 * Connect to a transmission_server.c instance
 * and send a message
 */

int main(void)
{
  int ret;
  int sfd;
  char* buf = "abcde";

  ret = sfd = create_inet_stream_socket("127.0.0.1","1111",LIBSOCKET_IPv4,0);

  if (ret < 0) {
    perror(0);
    exit(1);
  }

  ret = write(sfd,buf,5);
  if (ret < 0) {
    perror(0);
    exit(1);
  }

  ret = destroy_inet_socket(sfd);

  if (ret < 0) {
    perror(0);
    exit(1);
  }

  return 0;
}
