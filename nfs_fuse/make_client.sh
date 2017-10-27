libfuse=`pkg-config fuse --cflags --libs`
gcc client/client.c common/headers.h third_party/log.c/src/log.h third_party/log.c/src/log.c -lsocket $libfuse -o build/client -g -O0

