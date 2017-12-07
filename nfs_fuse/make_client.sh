libfuse=`pkg-config fuse --cflags --libs`
libhiredis=`pkg-config hiredis --cflags --libs`
headers="common/headers.h"
log="third_party/log.c/src/log.h third_party/log.c/src/log.c"
cache="client/cache.h client/cache.c"
client="client/client.c"

gcc $client $cache $log $headers -lsocket -lcrypto $libfuse $libhiredis -o build/client -O3 -g
