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
  FUSE_OPT_END
};

// Automatically initialized to 0.
static const char testblock[sizeof(struct stat)];

void make_request(const char* path, int req_type) {
  log_trace("Making a request (code %d) for %s", req_type, path);
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
    if (save_metadata(path, O_CREAT | O_WRONLY | O_TRUNC, resp.sb) == -1)
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
             memcmp(&resp.sb, testblock, sizeof(struct stat)) == 0) {
    save_stat(path, resp.sb);
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
             memcmp(&resp.sb, testblock, sizeof(struct stat)) == 0) {
    save_stat(path, resp.sb);
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

  // TODO Save just stats buffer to cache? If we never opened the file...
  if (!cache_enabled || ret != 0) {
    make_request(path, NFS_FUSE_REQUEST_GETATTR);

    response_getattr_t resp;
    read(sfd, &resp, sizeof(response_getattr_t));

    if (resp.ret != 0) {
      ret = -resp.ret;
      log_error("Fuse Getattr for %s failed: %s", path, strerror(resp.ret));
    } else {
      ret = 0;
      memcpy(stbuf, &resp.sb, sizeof(struct stat));
      save_stat(path, resp.sb);
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

static int nfs_fuse_open(const char* path,
                         struct fuse_file_info* fi) {
  log_trace("Fuse Call: Open %s", path);

  make_request(path, NFS_FUSE_REQUEST_OPEN);

  request_open_t req;
  req.flags = fi->flags;
  write(sfd, &req, sizeof(request_open_t));

  response_open_t resp;
  read(sfd, &resp, sizeof(response_open_t));

  int ret = resp.ret;
  if (resp.ret != 0) {
    log_error("Fuse Open for %s failed: %s", path, strerror(resp.ret));
    ret = -resp.ret;
  } else if (cache_enabled) {
    int flags;
    struct stat sb;
    if (load_metadata(path, &flags, &sb) != 0) {
      // TODO Support multiple open files on same client by using file handles.
      // Trick: just merge open flags so both opens work.
      req.flags |= flags;
      if (req.flags & O_RDWR ||
          (req.flags & O_RDONLY && req.flags & O_WRONLY)) {
        req.flags &= (O_RDONLY ^ 1) && (O_WRONLY ^ 1);
        req.flags |= O_RDWR;
      }

      // Invalidate cache if it was modified by other sources.
      if (memcmp(&sb.st_mtim, &resp.sb.st_mtim, sizeof(struct timespec)) != 0)
        remove_file(path);
    }

    save_metadata(path, req.flags, resp.sb);
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

  int ret;
  int open_flags;

  request_read_t req;
  req.size = size;
  req.offset = offset;
  // First check if file is in cache
  if (cache_enabled) {
    ret = load_open_flags(path, &open_flags);
    if (ret == 0) {
      if (!((open_flags & O_RDONLY) ||
            (open_flags & O_RDWR)))
        return -EBADF;

      ret = load_file(path, offset, size, buf);
      if (ret != 0)
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

  if (!cache_enabled || ret != 0) {
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

        save_file(path, req.offset, resp_read.size, buf);

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
    log_error("Read dir for %s failed: %s", path, strerror(errno));
    return -resp.ret;
  }

  log_debug("We have %d entries on this folder", resp.size);
  int i;
  for (i = 0; i < resp.size; i++) {
    response_readdir_entry_t resp_entry;
    read(sfd, &resp_entry, sizeof(response_readdir_entry_t));

    char* name = malloc(resp_entry.name_l + 1);
    read(sfd, name, resp_entry.name_l);
    name[resp_entry.name_l] = '\0';

    filler(buf, name, &resp_entry.sb, 0);

    free(name);
  }

  log_trace("End Fuse Call Readdir");
  return -resp.ret;
}

static int nfs_fuse_release(const char* path,
                            struct fuse_file_info* fi) {
  log_trace("Fuse Call: Release %s", path);

  // No need to keep last_modify anymore.
  free((struct timespec *) fi->fh);

  make_request(path, NFS_FUSE_REQUEST_RELEASE);

  int ret = 0;
  read(sfd, &ret, sizeof(int));
  if (ret != 0) {
    log_error("Release for %s failed: %s", path, strerror(ret));
  } else if (cache_enabled) {
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
  log_trace("Fuse Call: Truncate %s", path);

  make_request(path, NFS_FUSE_REQUEST_TRUNCATE);

  request_truncate_t req_trunc;
  req_trunc.offset = offset;
  write(sfd, &req_trunc, sizeof(request_truncate_t));

  response_truncate_t resp;
  read(sfd, &resp, sizeof(response_truncate_t));
  if (resp.ret != 0) {
    log_error("Truncate failed: %s", strerror(resp.ret));
  } else if (cache_enabled &&
             memcmp(&resp.sb, testblock, sizeof(struct stat)) == 0) {
    save_stat(path, resp.sb);
  }

  log_trace("End Fuse Call Truncate");
  return resp.ret;
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
             memcmp(&resp.sb, testblock, sizeof(struct stat) == 0)) {
    save_stat(path, resp.sb);
  }

  log_trace("End Fuse Call Utimens");
  return -resp.ret;
}

static int nfs_fuse_write(const char* path,
                          const char* buf,
                          size_t size,
                          off_t offset,
                          struct fuse_file_info* fi) {
  log_trace("Fuse Call: Write %s", path);

  make_request(path, NFS_FUSE_REQUEST_WRITE);

  request_write_t* req_write = malloc(sizeof(request_write_t) + size);
  req_write->size = size;
  memcpy(req_write->data, buf, size);
  write(sfd, req_write, sizeof(request_write_t) + size);
  free(req_write);

  response_write_t resp_write;
  read(sfd, &resp_write, sizeof(response_write_t));

  int ret;
  if (resp_write.ret != 0) {
    log_error("Write for %s failed: %s", path, strerror(errno));
    ret = -resp_write.ret;
    if (cache_enabled) {
      save_stat(path, resp_write.sb);

      size_t cs = options.cache_chunk_size;
      off_t first_off = (offset/cs) * cs;
      off_t final_off =
          NFS_CLIENT_MIN(
              (((offset + size - 1)/cs) + 1) * cs,
              offset + resp_write.size);
      size_t tot_read = final_off - first_off;

      // TODO Optimze for writing chunks in the middle...
      char* newbuf = malloc(tot_read);
      load_file(path, first_off, tot_read, newbuf);
      memcpy(newbuf + offset - first_off, buf, resp_write.size);
      save_file(path, first_off, tot_read, newbuf);
    }
  } else {
    ret = resp_write.size;
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
  .readdir  = nfs_fuse_readdir,  // No cached
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
  log_set_level(LOG_TRACE);

  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

  options.server_addr = strdup("127.0.0.1");
  options.server_port = strdup("1111");
  options.redis_addr = strdup("127.0.0.1");
  options.redis_port = 6379;
  options.enable_cache = 1;
  options.cache_chunk_size = 4096;

  if (fuse_opt_parse(&args, &options, option_spec, NULL) == -1)
    return 1;

  return fuse_main(args.argc, args.argv, &nfs_fuse_oper, NULL);
}
