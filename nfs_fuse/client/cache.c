#include <hiredis/hiredis.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "cache.h"

#include "../third_party/log.c/src/log.h"

#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_PORT 6379

#define KILOBYTE 1024
#define MEGABYTE 1048576

#define STANDARD_CHUNK 4096

#define TIMESPEC_FIELD_NAME "last_modify"

// NOTE This doesn't allow for multiple things using the same "library", so
// possibly make a cache descriptor.
static redisContext* c;
size_t chunk_size = STANDARD_CHUNK;

int init_cache(const char* hostname, int port, size_t chunk_size_) {
  log_trace("Configuring Redis");
  if (hostname == NULL)
    hostname = DEFAULT_HOST;
  if (port == 0)
    port = DEFAULT_PORT;
  if (chunk_size_ != 0)
    chunk_size = chunk_size_;

  log_debug("Connecting on host: %s, port: %d", hostname, port);

  // TODO Fall back to another sort of storage?
  struct timeval timeout = { 1, 500000 }; // 1.5 seconds
  c = redisConnectWithTimeout(hostname, port, timeout);
  if (c == NULL || c->err) {
    if (c) {
      log_error("Cache: Redis Connection error: %s\n", c->errstr);
      redisFree(c);
    } else {
      log_error("Cache: Redis Connection error: can't alloc redis context\n");
    }
    return -1;
  }
  return clear_cache();
  log_trace("End Configuring Redis");
}

static int load_chunk(char* sha1_key, size_t chunk_n, char* chunk_data) {
  redisReply* reply =
      redisCommand(c, "hget %b %d", sha1_key, SHA_DIGEST_LENGTH, chunk_n);
  if (reply == NULL) {
    log_debug("key-chunk didn't exist");
    return -1;
  } else if (reply->type != REDIS_REPLY_STRING || reply->len != chunk_size) {
    log_error("Redis item was modified by outside sources?");
    freeReplyObject(reply);
    return -2;
  }

  memcpy(chunk_data, reply->str, chunk_size);
  return 0;
}

static int load_timespec(char* sha1_key, struct timespec* out) {
  redisReply* reply =
      redisCommand(c, "hget %b %d",
                   sha1_key,
                   SHA_DIGEST_LENGTH,
                   TIMESPEC_FIELD_NAME);
  if (reply == NULL) {
    log_error("timespec wasn't set");
    return -1;
  } else if (reply->type != REDIS_REPLY_STRING || reply->len != chunk_size) {
    log_error("Redis item was modified by outside sources?");
    freeReplyObject(reply);
    return -2;
  }

  memcpy(out, reply->str, sizeof(struct timespec));
  return 0;
}

int clear_cache() {
  redisReply* reply = redisCommand(c, "FLUSHALL");
  int ret;
  if (reply == NULL) {
    log_error("Didn't get a reply from redis - is it connected?");
    ret = -1;
  } else if (reply->type != REDIS_REPLY_STATUS) {
    log_error("Redis behaved in an unknown way.");
    ret = -1;
  } else {
    ret = reply->integer;
  }

  freeReplyObject(reply);
  return ret;
}

int load_last_modify(char* path, size_t path_l, off_t offset,
                     struct timespec* out) {
  log_trace("Loading last modification");
  unsigned char key_string[SHA_DIGEST_LENGTH];
  SHA1(path, path_l, key_string);
  return load_timespec(key_string, out);
}

int save_file(char* path, size_t path_l, off_t offset,
              char* in_data, size_t size, struct timespec last_m) {
  log_trace("Saving file");
  unsigned char key_string[SHA_DIGEST_LENGTH];
  SHA1(path, path_l, key_string);

  redisReply* tmReply =
      redisCommand(c, "hset %b %s %b",
                   key_string, SHA_DIGEST_LENGTH, TIMESPEC_FIELD_NAME,
                   &last_m, sizeof(struct timespec));
  // TODO Do we need error checking here?
  freeReplyObject(tmReply);

  size_t chunk_number;
  off_t curr_off_data = 0;
  for (chunk_number = offset/chunk_size;
       chunk_number * chunk_size <= offset + size;
       chunk_number++) {
    log_debug("Doing chunk number %ld", chunk_number);

    char buff[chunk_size];
    memset(buff, 0, chunk_size);

    // First item of for loop -> might not be writing the entire chunk.
    // Last item of for loop -> might not be writing the entire chunk.
    if (chunk_number == (offset/chunk_size) && offset != 0) {
      int ret = load_chunk(key_string, chunk_number, buff);

      int chk_off = offset - (chunk_number * chunk_size);
      memcpy(buff + chk_off, in_data + curr_off_data, chunk_size - chk_off);
      curr_off_data += chunk_size - chk_off;
    } else if ((chunk_number + 1) * chunk_size > offset + size) {
      int ret = load_chunk(key_string, chunk_number, buff);

      memcpy(buff, in_data + curr_off_data, offset + size - (chunk_number * chunk_size));
      curr_off_data += offset + size - (chunk_number * chunk_size);
    } else {
      memcpy(buff, in_data + curr_off_data, chunk_size);
      curr_off_data += chunk_size;
    }

    redisReply* reply;
    reply = redisCommand(c, "hset %b %d %b", key_string, SHA_DIGEST_LENGTH, chunk_number,
                         buff, chunk_size);

    // Error checking
    if (reply == NULL) {
      return -1;
    } else if (reply->type != REDIS_REPLY_INTEGER || reply->integer != 0) {
      freeReplyObject(reply);
      return -1;
    }
    freeReplyObject(reply);
  }

  log_trace("End save file");
  return 0;
}

int load_file(char* path, size_t path_l, off_t offset,
              char* out_data, size_t size) {
  log_trace("Loading file");
  unsigned char key_string[SHA_DIGEST_LENGTH];
  SHA1(path, path_l, key_string);

  size_t chunk_number;
  off_t curr_off_data = 0;
  for (chunk_number = offset/chunk_size;
       chunk_number * chunk_size <= offset + size;
       chunk_number++) {
    char buff[chunk_size];
    int ret = load_chunk(key_string, chunk_number, buff);
    if (ret != 0)
      return -1;

    // First item of for loop -> might not be writing the entire chunk.
    // Last item of for loop -> might not be writing the entire chunk.
    if (chunk_number == (offset/chunk_size) && offset != 0) {
      int chk_off = offset - (chunk_number * chunk_size);
      memcpy(out_data + curr_off_data, buff + chk_off, chunk_size - chk_off);
      curr_off_data += chunk_size - chk_off;
    } else if ((chunk_number + 1) * chunk_size > offset + size) {
      memcpy(out_data + curr_off_data, buff, offset + size - (chunk_number * chunk_size));
      curr_off_data += offset + size - (chunk_number * chunk_size);
    } else {
      memcpy(out_data, buff, chunk_size);
      curr_off_data += chunk_size;
    }
  }

  log_trace("End load file");
  return 0;
}

