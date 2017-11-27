#define FUSE_USE_VERSION 26

#include <fuse.h>

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <libsocket/libinetsocket.h>

#include "cache.h"
#include "../common/headers.h"
#include "../third_party/log.c/src/log.h"

#define CACHE_ENABLED_DEFAULT 1

#define NFS_CLIENT_MIN(a, b) ((a) < (b)) ? (a) : (b)
#define NFS_CLIENT_MAX(a, b) ((a) > (b)) ? (a) : (b)

static int sfd;
static int cache_enabled = CACHE_ENABLED_DEFAULT;
static size_t cache_chunk_size = 0;

static struct options {
  const char* server_addr;
  const char* server_port;
  const char* redis_addr;
  int redis_port;
  int enable_cache;
  size_t cache_chunk_size;
  int cache_check_time;

  int help;
  int debug;
} options;

#define OPTION(t, p, b) { t, offsetof(struct options, p), b }
static const struct fuse_opt option_spec[] = {
  OPTION("--server-addr=%s", server_addr, 0),
  OPTION("--server-port=%s", server_port, 0),
  OPTION("--redis-addr=%s", redis_addr, 0),
  OPTION("--redis-port=%s", redis_port, 0),
  OPTION("--enable-cache", enable_cache, 1),
  OPTION("--noenable-cache", enable_cache, 0),
  OPTION("--cache-size=%lu", cache_chunk_size, 0),
  OPTION("--cache-check-time=%d", cache_check_time, 0),
  OPTION("--help", help, 1),
  OPTION("--debug", debug, 1),
  FUSE_OPT_END
};

// Automatically initialized to 0.
static const char testblock[sizeof(struct stat)];

void make_request(const char* path, int req_type) {
  log_info("Making a request (code %d) for %s", req_type, path);
  size_t path_l = strlen(path);

  request_t* req = malloc(sizeof(request_t) + path_l);
  req->type = req_type;
  req->path_l = path_l;
  memcpy(req->path, path, path_l);

  size_t req_size = sizeof(request_t) + path_l;
  log_trace("Sending request of size %d", req_size);
  write(sfd, req, req_size);

  free(req);
}

static int nfs_fuse_create(const char* path,
                           mode_t mode,
                           struct fuse_file_info* fi) {
  log_trace("Fuse Call: Create %s", path);

  make_request(path, NFS_FUSE_REQUEST_CREATE);

  request_create_t req;
  req.mode = mode;
  write(sfd, &req, sizeof(request_create_t));

  response_create_t resp;
  read(sfd, &resp, sizeof(response_create_t));

  int ret = resp.ret;
  if (resp.ret != 0) {
    log_error("Fuse Create for %s failed: %s", path, strerror(resp.ret));
    ret = -resp.ret;
  } else if (cache_enabled) {
    remove_file(path);
    if (save_metadata(path, O_CREAT | O_WRONLY | O_TRUNC, &resp.sb) == -1)
      log_error("Couldn't save metadata for %s", path);
  }

  log_trace("End Fuse Call Create");
  return -resp.ret;
}

static int nfs_fuse_chmod(const char* path,
                          mode_t mode) {
  log_trace("Fuse Call: Chmod %s", path);

  make_request(path, NFS_FUSE_REQUEST_CHMOD);

  request_chmod_t req_chmod;
  req_chmod.mode = mode;
  write(sfd, &req_chmod, sizeof(request_chmod_t));

  response_chmod_t resp;
  read(sfd, &resp, sizeof(response_chmod_t));
  if (resp.ret != 0) {
    log_error("Fuse Chmod for %s failed: %s", path, strerror(resp.ret));
  } else if (cache_enabled &&
             memcmp(&resp.sb, testblock, sizeof(struct stat)) != 0) {
    save_stat(path, &resp.sb);
  }

  log_trace("End Fuse Call Chmod");
  return -resp.ret;
}

static int nfs_fuse_chown(const char* path,
                          uid_t uid, gid_t gid) {
  log_trace("Fuse Call: Chown %s", path);

  make_request(path, NFS_FUSE_REQUEST_CHOWN);

  request_chown_t req_chown;
  req_chown.uid = uid;
  req_chown.gid = gid;
  write(sfd, &req_chown, sizeof(request_chown_t));

  response_chown_t resp;
  read(sfd, &resp, sizeof(response_chown_t));
  if (resp.ret != 0) {
    log_error("Fuse Chown for %s failed: %s", path, strerror(resp.ret));
  } else if (cache_enabled &&
             memcmp(&resp.sb, testblock, sizeof(struct stat)) != 0) {
    save_stat(path, &resp.sb);
  }

  log_trace("End Fuse Call Chown");
  return -resp.ret;
}

static void nfs_fuse_destroy(void* arg) {
  log_trace("Fuse Call: Destroy");
  make_request("", NFS_FUSE_REQUEST_DESTROY);
  close_cache();
  log_trace("End Fuse Call Destroy");
}

static void* nfs_fuse_init(struct fuse_conn_info* conn) {
  log_trace("Fuse Call: Init");

  // TODO Allow for external IP.
  sfd = create_inet_stream_socket(options.server_addr,
                                  options.server_port,
                                  LIBSOCKET_IPv4, 0);
  if (sfd < 0) {
    log_fatal("Failed to start fuse connection: %s", strerror(errno));
    exit(1);
  }
  log_trace("Socket up and running");

  if (init_cache(options.redis_addr,
                 options.redis_port,
                 options.cache_chunk_size) == -1) {
    log_fatal("Could not initialize cache.");
    exit(1);
  }
  options.cache_chunk_size = get_chunk_size();
  log_trace("Cache up and running");

  return NULL;
}

static int nfs_fuse_getattr(const char* path,
                            struct stat* stbuf) {
  log_trace("Fuse Call: Getattr %s", path);

  int ret = 0;
  if (cache_enabled)
    ret = load_stat(path, stbuf);

  if (!cache_enabled || ret == -1) {
    make_request(path, NFS_FUSE_REQUEST_GETATTR);

    response_getattr_t resp;
    read(sfd, &resp, sizeof(response_getattr_t));

    if (resp.ret != 0) {
      ret = -resp.ret;
      log_error("Fuse Getattr for %s failed: %s", path, strerror(resp.ret));
    } else {
      ret = 0;
      memcpy(stbuf, &resp.sb, sizeof(struct stat));
      save_stat(path, &resp.sb);
    }
  }

  log_trace("End Fuse Call Getattr");
  return ret;
}

static int nfs_fuse_mkdir(const char* path,
                          mode_t mode) {
  log_trace("Fuse Call: Mkdir %s", path);

  make_request(path, NFS_FUSE_REQUEST_MKDIR);

  request_mkdir_t req_mkdir;
  req_mkdir.mode = mode;
  write(sfd, &req_mkdir, sizeof(request_mkdir_t));

  int ret = 0;
  read(sfd, &ret, sizeof(int));
  if (ret != 0) log_error("Fuse Mkdir for %s failed: %s", path, strerror(ret));

  log_trace("End Fuse Call Mkdir");
  return -ret;
}

static int simple_open_request(const char* path, int flags,
                               response_open_t* resp) {
  make_request(path, NFS_FUSE_REQUEST_OPEN);
  request_open_t req;
  req.flags = flags;
  write(sfd, &req, sizeof(request_open_t));
  read(sfd, resp, sizeof(response_open_t));
  return resp->ret;
}

// TODO Support individual open flags wth file handlers.
static int nfs_fuse_open(const char* path,
                         struct fuse_file_info* fi) {
  log_trace("Fuse Call: Open %s", path);

  int ret = 0;
  if (cache_enabled) {
    int open_flags;
    struct stat sb;
    ret = load_metadata(path, &open_flags, &sb);

    // Check if we should invalidate cache.
    if (ret != -1) {
      struct timespec curr_time;
      clock_gettime(CLOCK_REALTIME, &curr_time);

      double diff1 = difftime(curr_time.tv_sec, sb.st_atim.tv_sec);
      double diff2 = difftime(curr_time.tv_sec, sb.st_mtim.tv_sec);
      log_debug("what %.5lf and %.5lf :)", diff1, diff2);
      if (diff1 > options.cache_check_time &&
          diff2 > options.cache_check_time) {
        log_debug("Checking file curr timespec.");
        response_open_t resp;
        ret = simple_open_request(path, fi->flags, &resp);

        if (resp.ret == 0) {
          if (sb.st_mtim.tv_sec != resp.sb.st_mtim.tv_sec) {
            log_debug("Invalidated cache for %s", path);
            remove_file(path);
          }

          // Updated last access time locally so we don't repeat cache check.
          // Trick lol.
          resp.sb.st_atim = curr_time;
          save_metadata(path, fi->flags, &resp.sb);
        }
      } else {
        int new_flags;

        open_flags = open_flags & (O_RDONLY | O_WRONLY | O_RDWR);
        fi->flags = fi->flags & (O_RDONLY | O_WRONLY | O_RDWR);

        new_flags = (open_flags | fi->flags);
        if (((new_flags & O_RDONLY) && (new_flags & O_WRONLY)) ||
            (new_flags & O_RDWR)) {
          new_flags &= (~O_RDONLY) && (~O_WRONLY);
          new_flags |= O_RDWR;
        }
        log_trace("flags after trick: %x", new_flags);

        save_open_flags(path, new_flags);
      }
    } else
      log_debug("Cache read failed.");
  }

  if (!cache_enabled || ret != 0) {
    // Basically sanity check to see if file exists/is accessible.
    ret = 0;
    response_open_t resp;
    simple_open_request(path, fi->flags, &resp);

    if (resp.ret == -1) {
      log_error("Fuse Open for %s failed: %s", path, strerror(resp.ret));
      ret = -resp.ret;
    } else if (cache_enabled) {
      save_metadata(path, fi->flags, &resp.sb);
    }
  }

  log_trace("End Fuse Call Open");
  return ret;
}

static int nfs_fuse_read(const char* path,
                         char* buf,
                         size_t size,
                         off_t offset,
                         struct fuse_file_info* fi) {
  log_trace("Fuse Call: Read %s", path);

  int ret = 0;
  int open_flags;

  request_read_t req;
  req.size = size;
  req.offset = offset;
  // First check if file is in cache
  if (cache_enabled) {
    ret = load_open_flags(path, &open_flags);
    if (ret != -1) {
//      if (!((open_flags & O_RDONLY) ||
//            (open_flags & O_RDWR)))
//        return -EBADF;

      ret = load_file(path, offset, size, buf);
      if (ret == -1)
        log_error("Failed to read from cache.");
    } else {
      size_t cs = options.cache_chunk_size;
      off_t first_off = (offset/cs) * cs;
      off_t final_off =
          (((offset + size - 1)/cs) + 1) * cs;
      size_t tot_read = final_off - first_off;
      log_debug("Reading with cache from %lu to %lu", first_off, final_off);

      req.offset = first_off;
      req.size = tot_read;
    }
  }

  if (!cache_enabled || ret == -1) {
    make_request(path, NFS_FUSE_REQUEST_READ);
    write(sfd, &req, sizeof(request_read_t));

    response_read_t resp_read;
    read(sfd, &resp_read, sizeof(resp_read));
    if (resp_read.ret != 0) {
      ret = -resp_read.ret;
      log_error("Read for %s failed: %s", path, strerror(errno));
    } else {
      ret = resp_read.size;
      log_trace("Read %lu bytes", resp_read.size);

      if (cache_enabled) {
        char* retbuf = malloc(resp_read.size);
        read(sfd, retbuf, resp_read.size);

        save_file(path, req.offset, resp_read.size, retbuf);

        size_t read_from_requested =
          NFS_CLIENT_MIN(req.offset + resp_read.size - offset, size);
        if (read_from_requested < 0)
          read_from_requested = 0;

        memcpy(buf,
               retbuf + offset - req.offset,
               read_from_requested);
        ret = read_from_requested;
        log_debug("With cache: read %lu", read_from_requested);
      } else {
        read(sfd, buf, resp_read.size);
      }
    }
  }

  log_trace("End Fuse Call Read");
  return ret;
}

static int nfs_fuse_readdir(const char* path,
                            void* buf,
                            fuse_fill_dir_t filler,
                            off_t offset,
                            struct fuse_file_info* fi) {
  log_trace("Fuse Call: Readdir %s", path);

  make_request(path, NFS_FUSE_REQUEST_READDIR);

  response_readdir_t resp;
  read(sfd, &resp, sizeof(response_readdir_t));

  if (resp.ret != 0) {
    log_error("Read dir for %s failed: %s", path, strerror(resp.ret));
    return -resp.ret;
  }

  log_debug("We have %d entries on this folder", resp.size);
  size_t i;
  for (i = 0; i < resp.size; i++) {
    response_readdir_entry_t resp_entry;
    read(sfd, &resp_entry, sizeof(response_readdir_entry_t));

    char* name = malloc(resp_entry.name_l + 1);
    read(sfd, name, resp_entry.name_l);
    name[resp_entry.name_l] = '\0';

    filler(buf, name, &resp_entry.sb, 0);
    save_stat(name, &resp_entry.sb);

    free(name);
  }

  log_trace("End Fuse Call Readdir");
  return -resp.ret;
}

static int nfs_fuse_release(const char* path,
                            struct fuse_file_info* fi) {
  log_trace("Fuse Call: Release %s", path);

  int ret = 0;
  if (cache_enabled) {
    save_open_flags(path, 0);
  }

  log_trace("End Fuse Call Release");
  return -ret;
}

static int nfs_fuse_rmdir(const char* path) {
  log_trace("Fuse Call: Rmdir %s", path);

  make_request(path, NFS_FUSE_REQUEST_RMDIR);

  int ret = 0;
  read(sfd, &ret, sizeof(int));
  if (ret != 0) log_error("Rmdir for %s failed: %s", path, strerror(ret));

  log_trace("End Fuse Call Rmdir");
  return -ret;
}

static int nfs_fuse_statfs(const char* path,
                           struct statvfs* stbuf) {
  log_trace("Fuse Call: StatFs %s", path);

  make_request(path, NFS_FUSE_REQUEST_STATVFS);

  response_statvfs_t resp;
  read(sfd, &resp, sizeof(response_statvfs_t));
  memcpy(stbuf, &resp.sb, sizeof(struct statvfs));

  if (resp.ret != 0) log_error("Statfs failed: %s", strerror(resp.ret));

  log_trace("End Fuse Call StatFs");
  return -resp.ret;
}

static int nfs_fuse_truncate(const char* path,
                             off_t offset) {
  log_trace("Fuse Call: Truncate %s with off %lu", path, offset);

  make_request(path, NFS_FUSE_REQUEST_TRUNCATE);

  request_truncate_t req_trunc;
  req_trunc.offset = offset;
  write(sfd, &req_trunc, sizeof(request_truncate_t));

  response_truncate_t resp;
  read(sfd, &resp, sizeof(response_truncate_t));
  if (resp.ret != 0) {
    log_error("Truncate failed: %s", strerror(resp.ret));
  } else if (cache_enabled &&
             memcmp(&resp.sb, testblock, sizeof(struct stat)) != 0) {
    save_stat(path, &resp.sb);
  }

  log_trace("End Fuse Call Truncate");
  return -resp.ret;
}

static int nfs_fuse_unlink(const char* path) {
  log_trace("Fuse Call: Unlink %s", path);

  make_request(path, NFS_FUSE_REQUEST_UNLINK);

  int ret = 0;
  read(sfd, &ret, sizeof(int));
  if (ret != 0) {
    log_error("Unlink failed: %s", strerror(ret));
  } else if (cache_enabled) {
    remove_file(path);
  }

  log_trace("End Fuse Call Unlink");
  return -ret;
}

static int nfs_fuse_utimens(const char* path,
                            const struct timespec tv[2]) {
  log_trace("Fuse Call: Utimens %s", path);

  make_request(path, NFS_FUSE_REQUEST_UTIMENS);
  write(sfd, tv, 2*sizeof(struct timespec));

  response_utimens_t resp;
  read(sfd, &resp, sizeof(response_utimens_t));
  if (resp.ret != 0) {
    log_error("Fuse Utimens for %s failed: %s", path, strerror(resp.ret));
  } else if (cache_enabled &&
             memcmp(&resp.sb, testblock, sizeof(struct stat) != 0)) {
    save_stat(path, &resp.sb);
  }

  log_trace("End Fuse Call Utimens");
  return -resp.ret;
}

static int nfs_fuse_write(const char* path,
                          const char* buf,
                          size_t size,
                          off_t offset,
                          struct fuse_file_info* fi) {
  log_trace("Fuse Call: Write %s at off %lu with size %lu", path, offset, size);

  make_request(path, NFS_FUSE_REQUEST_WRITE);

  size_t tot_req = sizeof(request_write_t) + size;

  request_write_t* req_write = malloc(tot_req);
  req_write->size = size;
  req_write->offset = offset;
  memcpy(req_write->data, buf, size);
  write(sfd, req_write, tot_req);
  free(req_write);

  response_write_t resp_write;
  read(sfd, &resp_write, sizeof(response_write_t));

  int ret = 0;
  if (resp_write.ret != 0) {
    log_error("Write for %s failed: %s", path, strerror(errno));
    ret = -resp_write.ret;
  } else {
    ret = resp_write.size;
    log_debug("Wrote %lu bytes", ret);
    if (cache_enabled) {
      size_t cs = options.cache_chunk_size;
      off_t first_off = (offset/cs) * cs;
      off_t final_off = (((offset + resp_write.size - 1)/cs) + 1) * cs;
      size_t tot_read = final_off - first_off;
      char* newbuf = malloc(tot_read);

      log_debug("Write to cache from %lu to %lu", first_off, final_off);

      // TODO Optmize for writing chunks in the middle...
      // If the file wasn't on cache to begin with, don't bother populating rn.
      int act_read = load_file(path, first_off, tot_read, newbuf);
      if (act_read != -1) {
        // Hopefull won't leave empty chunks...
        memcpy(newbuf + offset - first_off, buf, resp_write.size);

        log_debug("Saving stats...");
        save_stat(path, &resp_write.sb);
        size_t final_write_size =
            NFS_CLIENT_MAX(act_read, offset + resp_write.size - first_off);
        log_debug("Saving file with %lu bytes...", final_write_size);
        save_file(path, first_off, final_write_size, newbuf);
      }
    }
  }

  log_trace("End Fuse Call Write");
  return ret;
}

static struct fuse_operations nfs_fuse_oper = {
  .create   = nfs_fuse_create,   // DONE
  .chmod    = nfs_fuse_chmod,    // DONE
  .chown    = nfs_fuse_chown,    // DONE
  .destroy  = nfs_fuse_destroy,  // DONE
  .init     = nfs_fuse_init,
  .getattr  = nfs_fuse_getattr,  // DONE
  .mkdir    = nfs_fuse_mkdir,    // Not Cache
  .open     = nfs_fuse_open,     // DONE
  .read     = nfs_fuse_read,     // DONE
  .readdir  = nfs_fuse_readdir,  // DONE
  .release  = nfs_fuse_release,  // DONE
  .rmdir    = nfs_fuse_rmdir,    // Not Cached
  .statfs   = nfs_fuse_statfs,   // Not Cached
  .truncate = nfs_fuse_truncate, // DONE
  .unlink   = nfs_fuse_unlink,   // DONE
  .utimens  = nfs_fuse_utimens,  // DONE
  .write    = nfs_fuse_write,    // DONE

  // .flag_nullpath_ok = 1, // Yay file handles.
};

int main(int argc, char* argv[]) {
  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

  options.server_addr = strdup("127.0.0.1");
  options.server_port = strdup("1111");
  options.redis_addr = strdup("127.0.0.1");
  options.redis_port = 6379;
  options.enable_cache = 1;
  options.cache_chunk_size = 4096;
  options.cache_check_time = 600;
  options.help = 0;
  options.debug = 0;

  if (fuse_opt_parse(&args, &options, option_spec, NULL) == -1)
    return 1;

  if (options.debug)
    log_set_level(LOG_TRACE);

  cache_enabled = options.enable_cache;

  if (options.help) {
    // TODO Print help.
    return 0;
  }

  return fuse_main(args.argc, args.argv, &nfs_fuse_oper, NULL);
}
