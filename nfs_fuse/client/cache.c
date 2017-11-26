#include <hiredis/hiredis.h>
#include <math.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "cache.h"

#include "../third_party/log.c/src/log.h"

#define NFS_REDIS_DEFAULT_HOST "127.0.0.1"
#define NFS_REDIS_DEFAULT_PORT 6379

#define NFS_REDIS_KILOBYTE 1024
#define NFS_REDIS_MEGABYTE 1048576

#define NFS_REDIS_STANDARD_CHUNK 4096

#define NFS_REDIS_OPEN_FIELD_NAME "open_flags"
#define NFS_REDIS_STAT_FIELD_NAME "stats"

#define NFS_REDIS_MIN(a, b) ((a) < (b)) ? (a) : (b)

// NOTE This doesn't allow for multiple things using the same "library", so
// possibly make a cache descriptor.
static redisContext* c;
static size_t chunk_size = NFS_REDIS_STANDARD_CHUNK;

int init_cache(const char* hostname, int port, size_t chunk_size_) {
  log_trace("Configuring Redis");
  if (hostname == NULL)
    hostname = NFS_REDIS_DEFAULT_HOST;
  if (port == 0)
    port = NFS_REDIS_DEFAULT_PORT;
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

int close_cache() {
  if (c)
    redisFree(c);
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

size_t get_chunk_size() {
  return chunk_size;
}

static int load_error_check(redisReply* reply, size_t expected_size) {
  if (reply == NULL) {
    log_debug("Key-chunk didn't exist");
    return -1;
  } else if (reply->type != REDIS_REPLY_STRING || reply->len != expected_size) {
    log_error("Redis item was modified by outside sources? Reply type: %d, Reply length: %d, expected length: %d",
              reply->type, reply->len, expected_size);
    return -1;
  }
  return 0;
}

// Field name must be \0 terminated.
static int save_common(const unsigned char* sha1_key, char* field_name,
                       void* in_data, size_t data_size) {
  log_trace("Saving field %s for key %s", field_name, sha1_key);
  redisReply* reply =
      redisCommand(c, "hset %b %s %b", sha1_key, SHA_DIGEST_LENGTH,
                   field_name, in_data, data_size);

  int ret = 0;
  if (reply == NULL || reply->type != REDIS_REPLY_INTEGER)
    ret = -1;
  freeReplyObject(reply);
  return ret;
}

static int load_common(const unsigned char* sha1_key,
                       char* field_name, off_t offset,
                       void* out_data, size_t out_size) {
  log_trace("Reading field %s for key %s", field_name, sha1_key);
  redisReply* reply =
      redisCommand(c, "hget %b %s", sha1_key, SHA_DIGEST_LENGTH, field_name);
  int ret = load_error_check(reply, out_size);
  if (ret == 0)
    memcpy(out_data, reply->str + offset, out_size);
  freeReplyObject(reply);
  return ret;
}

static int load_chunk(const unsigned char* sha1_key,
                      size_t chunk_n,
                      char* chunk_data) {
  log_trace("Reading chunk number %lu", chunk_n);
  char chunk_n_str[100];
  sprintf(chunk_n_str, "%lu", chunk_n);
  return load_common(sha1_key, chunk_n_str, 0, chunk_data, chunk_size);
}

static int load_chunk_data(const unsigned char* sha1_key,
                           size_t chunk_n,
                           char* chunk_data,
                           off_t offset,
                           size_t size) {
  log_trace("Reading chunk number %lu at offset %lu with total %lu",
            chunk_n, offset, size);
  char chunk_n_str[100];
  sprintf(chunk_n_str, "%lu", chunk_n);
  return load_common(sha1_key, chunk_n_str, offset, chunk_data, size);
}

static int save_open_flags_internal(const unsigned char* sha1_key, int open_flags) {
  log_trace("Saving open flags: %d", open_flags);
  return save_common(sha1_key, NFS_REDIS_OPEN_FIELD_NAME,
                     &open_flags, sizeof(int));
}

static int save_stat_internal(const unsigned char* sha1_key, struct stat sb) {
  return save_common(sha1_key, NFS_REDIS_STAT_FIELD_NAME,
                     &sb, sizeof(struct stat));
}

static int load_open_flags_internal(const unsigned char* sha1_key,
                              int* open_flags) {
  return load_common(sha1_key, NFS_REDIS_OPEN_FIELD_NAME, 0,
                     open_flags, sizeof(int));
}

static int load_stat_internal(const unsigned char* sha1_key,
                              struct stat* sb) {
  return load_common(sha1_key, NFS_REDIS_STAT_FIELD_NAME, 0,
                     sb, sizeof(struct stat));
}

int save_open_flags(const char* path, int open_flags) {
  unsigned char sha1_key[SHA_DIGEST_LENGTH];
  SHA1(path, strlen(path), sha1_key);
  return save_open_flags_internal(sha1_key, open_flags);
}

int save_stat(const char* path, struct stat sb) {
  unsigned char sha1_key[SHA_DIGEST_LENGTH];
  SHA1(path, strlen(path), sha1_key);
  return save_stat_internal(sha1_key, sb);
}

int load_open_flags(const char* path, int* open_flags) {
  unsigned char sha1_key[SHA_DIGEST_LENGTH];
  SHA1(path, strlen(path), sha1_key);
  return load_open_flags_internal(sha1_key, open_flags);
}

int load_stat(const char* path, struct stat* sb) {
  unsigned char sha1_key[SHA_DIGEST_LENGTH];
  SHA1(path, strlen(path), sha1_key);
  return load_stat_internal(sha1_key, sb);
}

int save_metadata(const char* path, int open_flags, struct stat sb) {
  log_trace("Saving metadata");

  unsigned char sha1_key[SHA_DIGEST_LENGTH];
  SHA1(path, strlen(path), sha1_key);

  int ret1 = save_open_flags_internal(sha1_key, open_flags);
  int ret2 = save_stat_internal(sha1_key, sb);
  if(ret1 != 0) log_error("Failed to save open flags for path: %s", path);
  if(ret2 != 0) log_error("Failed to save stat for path: %s", path); 

  return ret1 || ret2;
}

int load_metadata(const char* path, int* open_flags, struct stat* sb) {
  log_trace("Loading metadata");

  unsigned char sha1_key[SHA_DIGEST_LENGTH];
  SHA1(path, strlen(path), sha1_key);

  int ret1 = load_open_flags_internal(sha1_key, open_flags);
  int ret2 = load_stat_internal(sha1_key, sb);

  return ret1 || ret2;
}

static int save_error_check(const char* path, off_t offset, size_t size) {
  struct stat sb;
  if (load_stat(path, &sb) != 0) {
    log_error("Metadata should have been saved!");
    return -1;
  }

  size_t tot_l = sb.st_size;

  // We can only have a size that isn't a chunk size if this is the last block.
  if (offset % chunk_size != 0 ||
      (offset + size != tot_l && size % chunk_size != 0)) {
    log_error("Cannot handle data that doesn't fill entire chunks.");
    return -1;
  }
}

int save_file(const char* path, off_t offset, size_t size,
              const char* in_data) {
  log_trace("Saving file: %s at offset %lu with size %lu",
            path, offset, size);
  if (size == 0)
    return 0;

  unsigned char sha1_key[SHA_DIGEST_LENGTH];
  SHA1(path, strlen(path), sha1_key);

  if (save_error_check(path, offset, size) == -1)
    return -1;

  size_t chunk_number;
  for (chunk_number = offset/chunk_size;
       chunk_number * chunk_size <= offset + size - 1;
       chunk_number++) {
    log_debug("Doing chunk number %ld", chunk_number);

    size_t to_save =
        NFS_REDIS_MIN(chunk_size, offset + size - chunk_number * chunk_size);
    log_debug("Saving %lu bytes at chunk number %lu", to_save, chunk_number);

    redisReply* reply =
        redisCommand(c, "hset %b %d %b",
                     sha1_key, SHA_DIGEST_LENGTH,
                     chunk_number,
                     in_data + chunk_size * chunk_number - offset, to_save);

    // Error checking
    if (reply == NULL ||
        reply->type != REDIS_REPLY_INTEGER) {
      log_error("Redis saving failed. %d %d", reply->type, reply->integer);
      freeReplyObject(reply);
      return -1;
    }
    freeReplyObject(reply);
  }

  log_trace("End save file");
  return size;
}

int load_file(const char* path, off_t offset, size_t size,
              char* out_data) {
  log_trace("Loading file: %s at offset %lu with size %lu",
            path, offset, size);
  unsigned char sha1_key[SHA_DIGEST_LENGTH];
  SHA1(path, strlen(path), sha1_key);

  struct stat sb;
  if (load_stat(path, &sb) != 0) {
    log_error("Metadata should have been saved first!");
    return -1;
  }

  if (size == 0)
    return 0;

  size_t max_read = NFS_REDIS_MIN(sb.st_size, offset + size);

  size_t chunk_number;
  off_t curr_off_data = 0; // It's easier (and faster?) than recalculating at
                           // every iteration.
  for (chunk_number = offset/chunk_size;
       chunk_number * chunk_size < max_read;
       chunk_number++) {
    off_t chk_off =
        NFS_REDIS_MIN(offset - chunk_number * chunk_size, 0);
    size_t chk_end =
        NFS_REDIS_MIN(chunk_size, max_read - chunk_number * chunk_size);

    log_debug("Loading chunk number %lu from bytes %lu to %lu",
              chunk_number, chk_off, chk_end);

    int ret = load_chunk_data(sha1_key, chunk_number, out_data + curr_off_data,
                              chk_off, chk_end);
    if (ret != 0) {
      log_error("Failed loading chunk number %lu from bytes %lu to %lu",
                chunk_number, chk_off, chk_end);
      return -1;
    }
    curr_off_data += chk_end - chk_off;
  }

  log_trace("End load file");
  return max_read - offset > 0 ? max_read - offset : 0;
}

int remove_file(const char* path) {
  unsigned char sha1_key[SHA_DIGEST_LENGTH];
  SHA1(path, strlen(path), sha1_key);

  redisReply* reply = redisCommand(c, "DEL %b", sha1_key, SHA_DIGEST_LENGTH);
  if (reply == NULL ||
      reply->type != REDIS_REPLY_INTEGER ||
      reply->integer != 1) {
    return -1;
  }

  return 0;
}

