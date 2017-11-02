#include <hiredis/hiredis.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "cache.h"

#include "../third_party/log.c/src/log.h"

redisContext* c;

// TODO Maybe allow non-redis cache.
int init_cache() {
  log_trace("Configuring Redis");
  const char* hostname = "127.0.0.1";
  int port = 6739;

  // TODO Fall back to another sort of storage?
  struct timeval timeout = { 1, 500000 }; // 1.5 seconds
  c = redisConnectWithTimeout(hostname, port, timeout);
  if (c == NULL || c->err) {
    if (c) {
      log_error("Cache: Redis Connection error: %s\n", c->errstr);
      redisFree(c);
    } else {
      log_error("Cache: Redis Connection error: can't allocate redis context\n");
    }
    return -1;
  }
  log_trace("End Configuring Redis");
}

// TODO What if OS reads different offsets ???
int save_file(char* path, size_t path_l, off_t offset,
              char* data, size_t size) {
  // Pray no one will use > as part of the file name.
  unsigned char key_string[SHA_DIGEST_LENGTH + 1];
  SHA1(path, path_l, key_string);
  key_string[SHA_DIGEST_LENGTH] = '\0';

  /*redisReply* reply = redisCommand(c, "hget %s", key_string);*/

  char offset_str[100], size_str[100];
  sprintf(offset_str, "%ld", size);
  sprintf(size_str, "%ld", size);

  char offset_size[200];
  offset_size[0] = '\0';
  strcat(offset_size, offset_str);
  strcat(offset_size, ":");
  strcat(offset_size, size_str);

  char* data_with_0 = malloc(size + 1);
  memcpy(data_with_0, data, size);
  data_with_0[size] = '\0';

  log_debug("Sending to redis: hmset %s %s %s", key_string, offset_size, data_with_0);
  redisCommand(c, "hmset %s %s %s", key_string, offset_size, data_with_0);

  free(data_with_0);

  return 0;
}
