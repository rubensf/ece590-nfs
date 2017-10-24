#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <libsocket/libinetsocket.h>

int main(void)
{
  int sfd, bytes, ret;
  char src_host[128], src_service[7], buf[16];

  src_host[127] = 0;
  src_service[6] = 0;

  sfd = create_inet_server_socket("::", "1111", LIBSOCKET_TCP, LIBSOCKET_IPv6, 0);
  if (sfd == -1) {
    perror("Couldn't create server");
    exit(1);
  }
  printf("Socket up and running\n");

  while (1)
  {
    memset(buf,0,16);
    int cfd = accept_inet_stream_socket(sfd,src_host,127,src_service,6,LIBSOCKET_NUMERIC,0);
    if (cfd == -1) {
      perror("Couldn't accept connection");
      exit(1);
    }
    printf("Received an incoming connection.\n");

    bytes = read(cfd, buf, 15);

    if ( ret < 0 )
    {
      perror(0);
      exit(1);
    }

    printf("Connection from %s port %s: %s (%i)\n",src_host,src_service,buf,bytes);
    printf("Connection processed\n");
  }

  ret = destroy_inet_socket(sfd);

  if (ret < 0) {
    perror(0);
    exit(1);
  }

  return 0;
}
