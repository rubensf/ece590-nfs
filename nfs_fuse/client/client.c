#define FUSE_USE_VERSION 26

#include <fuse.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libsocket/libinetsocket.h>

#include "../common/headers.h"
#include "../third_party/log.c/src/log.h"

int sfd;

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

  request_create_t req_create;
  req_create.mode = mode;
  write(sfd, &req_create, sizeof(request_create_t));

  response_create_t resp_create;
  read(sfd, &resp_create, sizeof(response_create_t));
  if (resp_create.ret != 0) {
    log_error("Fuse Create for %s failed: %s", path, strerror(resp_create.ret));
  } else {
    fi->fh = resp_create.fd;
  }

  log_trace("End Fuse Call Create");
  return -resp_create.ret;
}

static int nfs_fuse_chmod(const char* path,
                          mode_t mode) {
  log_trace("Fuse Call: Chmod %s", path);

  make_request(path, NFS_FUSE_REQUEST_CHMOD);

  request_chmod_t req_chmod;
  req_chmod.mode = mode;
  write(sfd, &req_chmod, sizeof(request_chmod_t));

  int ret = 0;
  read(sfd, &ret, sizeof(int));
  if (ret != 0) log_error("Fuse Chmod for %s failed: %s", path, strerror(ret));

  log_trace("End Fuse Call Chmod");
  return -ret;
}

static int nfs_fuse_chown(const char* path,
                          uid_t uid, gid_t gid) {
  log_trace("Fuse Call: Chown %s", path);

  make_request(path, NFS_FUSE_REQUEST_CHOWN);

  request_chown_t req_chown;
  req_chown.uid = uid;
  req_chown.gid = gid;
  write(sfd, &req_chown, sizeof(request_chown_t));

  int ret = 0;
  read(sfd, &ret, sizeof(int));
  if (ret != 0) log_error("Fuse Chown for %s failed: %s", path, strerror(ret));

  log_trace("End Fuse Call Chown");
  return -ret;
}

static void* nfs_fuse_init(struct fuse_conn_info* conn) {
  log_trace("Fuse Call: Init");

  sfd = create_inet_stream_socket("127.0.0.1", "1111", LIBSOCKET_IPv4, 0);
  if (sfd < 0) {
    log_fatal("Failed to start fuse connection: %s", strerror(errno));
    exit(1);
  }
  log_trace("Socket up and running");
  log_trace("End Fuse Call Init");
  return NULL;
}

static int nfs_fuse_getattr(const char* path,
                            struct stat* stbuf) {
  log_trace("Fuse Call: Getattr %s", path);

  make_request(path, NFS_FUSE_REQUEST_GETATTR);

  response_getattr_t resp;
  read(sfd, &resp, sizeof(response_getattr_t));

  if (resp.ret != 0) 
    log_error("Fuse Getattr for %s failed: %s", path, strerror(resp.ret));

  memcpy(stbuf, &resp.sb, sizeof(struct stat));

  log_trace("End Fuse Call Getattr");
  return -resp.ret;
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

  response_open_t resp_open;
  read(sfd, &resp_open, sizeof(response_open_t));
  if (resp_open.ret != 0) {
    log_error("Open for %s failed: %s", path, strerror(resp_open.ret));
  } else {
    fi->fh = resp_open.fd;
  }

  log_trace("End Fuse Call Open");
  return -resp_open.ret;
}

static int nfs_fuse_read(const char* path,
                         char* buf,
                         size_t size,
                         off_t offset,
                         struct fuse_file_info* fi) {
  log_trace("Fuse Call: Read %s", path);

  make_request(path, NFS_FUSE_REQUEST_READ);

  request_read_t req_read;
  req_read.size = size;
  req_read.offset = offset;
  write(sfd, &req_read, sizeof(request_read_t));

  response_read_t resp_read;
  read(sfd, &resp_read, sizeof(resp_read));
  if (resp_read.ret != 0) {
    log_error("Read for %s failed: %s", path, strerror(errno));

    log_trace("End Fuse Call Read");
    return -resp_read.ret;
  } else {
    log_trace("Read %lu bytes", resp_read.size);
    read(sfd, buf, resp_read.size);

    log_trace("End Fuse Call Read");
    return resp_read.size;
  }
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

// TODO Debug: Not sure if it should work like this...
static int nfs_fuse_release(const char* path,
                            struct fuse_file_info* fi) {
  log_trace("Fuse Call: Release %s", path);

  make_request(path, NFS_FUSE_REQUEST_RELEASE);

  int ret = 0;
  read(sfd, &ret, sizeof(int));
  if (ret != 0) log_error("Release for %s failed: %s", path, strerror(ret));

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

  int ret = 0;
  read(sfd, &ret, sizeof(int));
  if (ret != 0) log_error("Truncate failed: %s", strerror(ret));

  log_trace("End Fuse Call Truncate");
  return ret;
}

static int nfs_fuse_unlink(const char* path) {
  log_trace("Fuse Call: Unlink %s", path);

  make_request(path, NFS_FUSE_REQUEST_UNLINK);

  int ret = 0;
  read(sfd, &ret, sizeof(int));
  if (ret != 0) log_error("Unlink failed: %s", strerror(ret));

  log_trace("End Fuse Call Unlink");
  return -ret;
}

static int nfs_fuse_utimens(const char* path,
                            const struct timespec tv[2]) {
  log_trace("Fuse Call: Utimens %s", path);

  make_request(path, NFS_FUSE_REQUEST_UTIMENS);
  write(sfd, tv, 2*sizeof(struct timespec));

  int ret = 0;
  read(sfd, &ret, sizeof(int));
  if (ret != 0) log_error("Utimens failed: %s", strerror(ret));

  log_trace("End Fuse Call Utimens");
  return -ret;
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
  } else {
    ret = resp_write.size;
  }

  log_debug("Write Returning %d", ret);
  log_trace("End Fuse Call Write");
  return ret;
}

static struct fuse_operations nfs_fuse_oper = {
  .create   = nfs_fuse_create,
  .chmod    = nfs_fuse_chmod,
  .chown    = nfs_fuse_chown,
  .init     = nfs_fuse_init,
  .getattr  = nfs_fuse_getattr,
  .mkdir    = nfs_fuse_mkdir,
  .open     = nfs_fuse_open,
  .read     = nfs_fuse_read,
  .readdir  = nfs_fuse_readdir,
  .release  = nfs_fuse_release,
  .rmdir    = nfs_fuse_rmdir,
  .statfs   = nfs_fuse_statfs,
  .truncate = nfs_fuse_truncate,
  .unlink   = nfs_fuse_unlink,
  .utimens  = nfs_fuse_utimens,
  .write    = nfs_fuse_write,
};

int main(int argc, char* argv[]) {
  log_set_level(LOG_TRACE);
  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
  return fuse_main(args.argc, args.argv, &nfs_fuse_oper, NULL);
}
