#define FUSE_USE_VERSION 31

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
  size_t path_l = strlen(path);

  request_t* req = malloc(sizeof(request_t) + path_l);
  req->type = req_type;
  req->path_l = path_l;
  memcpy(req->path, path, path_l);

  write(sfd, req, sizeof(request_t) + path_l);

  free(req);
}

static int nfs_fuse_create(const char* path,
                           mode_t mode,
                           struct fuse_file_info* fi) {
  log_debug("Fuse create %s", path);

  make_request(path, NFS_FUSE_REQUEST_CREATE);

  request_create_t req_create;
  req_create.mode = mode;
  write(sfd, &req_create, sizeof(request_create_t));

  int ret = 0;
  read(sfd, &ret, sizeof(int));
  if (ret != 0) log_error("Create failed: %s", strerror(ret));

  return -ret;
}

static int nfs_fuse_chmod(const char* path,
                          mode_t mode,
                          struct fuse_file_info* fi) {
  log_debug("Fuse chmod %s", path);

  make_request(path, NFS_FUSE_REQUEST_CREATE);

  request_chmod_t req_chmod;
  req_chmod.mode = mode;
  write(sfd, &req_chmod, sizeof(request_chmod_t));

  int ret = 0;
  read(sfd, &ret, sizeof(int));
  if (ret != 0) log_error("Chmod failed: %s", strerror(ret));

  return -ret;
}

static int nfs_fuse_chown(const char* path,
                          uid_t uid, gid_t gid,
                          struct fuse_file_info* fi) {
  log_debug("Fuse chown %s", path);

  make_request(path, NFS_FUSE_REQUEST_CREATE);

  request_chown_t req_chown;
  req_chown.uid = uid;
  req_chown.gid = gid;
  write(sfd, &req_chown, sizeof(request_chown_t));

  int ret = 0;
  read(sfd, &ret, sizeof(int));
  if (ret != 0) log_error("Chown failed: %s", strerror(ret));

  return -ret;
}

static void* nfs_fuse_init(struct fuse_conn_info* conn,
                           struct fuse_config* cfg) {
  log_debug("Fuse init");
  cfg->kernel_cache = 0;

  sfd = create_inet_stream_socket("127.0.0.1","1111",LIBSOCKET_IPv4,0);
  if (sfd < 0) {
    perror(0);
    exit(1);
  }
  log_trace("Socket up and running");

  return NULL;
}

static int nfs_fuse_getattr(const char* path,
                            struct stat* stbuf,
                            struct fuse_file_info* fh) {
  log_debug("Fuse Getattr %s", path);

  make_request(path, NFS_FUSE_REQUEST_GETATTR);

  response_getattr_t resp;
  read(sfd, &resp, sizeof(response_getattr_t));

  if (resp.ret != 0) {
    log_error("Failed get getattr: %s", strerror(resp.ret));
  }

  memcpy(stbuf, &resp.sb, sizeof(struct stat));
  return -resp.ret;
}

static int nfs_fuse_mkdir(const char* path,
                          mode_t mode) {
  log_debug("Fuse Mkdir %s", path);

  make_request(path, NFS_FUSE_REQUEST_MKDIR);

  request_mkdir_t req_mkdir;
  req_mkdir.mode = mode;
  write(sfd, &req_mkdir, sizeof(request_mkdir_t));

  int ret = 0;
  read(sfd, &ret, sizeof(int));
  if (ret != 0) log_error("Mkdir failed: %s", strerror(ret));

  return -ret;
}

// TODO Fix Ret.
static int nfs_fuse_read(const char* path,
                         char* buf,
                         size_t size,
                         off_t offset,
                         struct fuse_file_info* fi) {
  log_debug("Fuse Read %s", path);

  make_request(path, NFS_FUSE_REQUEST_READ);

  request_read_t req_read;
  req_read.size = size;
  req_read.offset = offset;
  write(sfd, &req_read, sizeof(request_read_t));

  response_read_t resp_read;
  read(sfd, &resp_read, sizeof(resp_read));
  if (resp_read.ret != 0) {
    log_trace("Read failed: %s", strerror(errno));
    return -resp_read.ret;
  }
  log_trace ("Ret %d", resp_read.ret);
  log_trace ("Read %lu bytes", resp_read.size);
  read(sfd, buf, resp_read.size);
  return resp_read.size;
}

// TODO Fix ret.
static int nfs_fuse_readdir(const char* path,
                            void* buf,
                            fuse_fill_dir_t filler,
                            off_t offset,
                            struct fuse_file_info* fi,
                            enum fuse_readdir_flags flags) {
  log_debug("Fuse Readdir %s", path);

  make_request(path, NFS_FUSE_REQUEST_READDIR);

  response_readdir_t resp;
  read(sfd, &resp, sizeof(response_readdir_t));

  if (resp.ret != 0)
    return resp.ret;

  log_debug("We have %d entries on this folder.", resp.size);
  int i;
  for (i = 0; i < resp.size; i++) {
    response_readdir_entry_t resp_entry;
    read(sfd, &resp_entry, sizeof(response_readdir_entry_t));
    log_debug("Name has length %d", resp_entry.name_l);

    char* name = malloc(resp_entry.name_l + 1);
    read(sfd, name, resp_entry.name_l);
    name[resp_entry.name_l] = '\0';

    log_debug("Found entry %s", name);
    filler(buf, name, &resp_entry.sb, 0, 0);

    free(name);
  }

  return -resp.ret;
}

static int nfs_fuse_rmdir(const char* path) {
  log_debug("Fuse Rmdir %s", path);

  make_request(path, NFS_FUSE_REQUEST_RMDIR);

  int ret = 0;
  read(sfd, &ret, sizeof(int));
  if (ret != 0) log_error("Rmdir failed: %s", strerror(ret));

  return -ret;
}

static int nfs_fuse_statfs(const char* path,
                           struct statvfs* stbuf) {
  log_debug("Fuse StatFs %s", path);

  make_request(path, NFS_FUSE_REQUEST_STATVFS);

  response_statvfs_t resp;
  read(sfd, &resp, sizeof(response_statvfs_t));
  memcpy(stbuf, &resp.sb, sizeof(struct statvfs));

  if (resp.ret != 0) log_error("Statfs failed: %s", strerror(resp.ret));

  return -resp.ret;
}

static int nfs_fuse_unlink(const char* path) {
  log_debug("Fuse Unlink %s", path);

  make_request(path, NFS_FUSE_REQUEST_UNLINK);

  int ret = 0;
  read(sfd, &ret, sizeof(int));
  if (ret != 0) log_error("Unlink failed: %s", strerror(ret));

  return -ret;
}

static int nfs_fuse_utimens(const char* path,
                            const struct timespec tv[2],
                            struct fuse_file_info* fi) {
  log_debug("Fuse utimens %s", path);

  make_request(path, NFS_FUSE_REQUEST_UTIMENS);
  write(sfd, tv, 2*sizeof(struct timespec));

  int ret = 0;
  read(sfd, &ret, sizeof(int));
  if (ret != 0) log_error("Utimens failed: %s", strerror(ret));

  return -ret;
}

// TODO Fix Ret
static int nfs_fuse_write(const char* path,
                          const char* buf,
                          size_t size,
                          off_t offset,
                          struct fuse_file_info* fi) {
  log_debug("Fuse Write %s", path);

  make_request(path, NFS_FUSE_REQUEST_WRITE);

  request_write_t* req_write = malloc(sizeof(request_write_t) + size);
  req_write->size = size;
  memcpy(req_write->data, buf, size);
  write(sfd, req_write, sizeof(request_write_t) + size);
  free(req_write);

  int resp_size;
  read(sfd, &resp_size, sizeof(int));

  return resp_size;
}

static struct fuse_operations nfs_fuse_oper = {
  .create  = nfs_fuse_create,
  .chmod   = nfs_fuse_chmod,
  .chown   = nfs_fuse_chown,
  .init    = nfs_fuse_init,
  .getattr = nfs_fuse_getattr,
  .mkdir   = nfs_fuse_mkdir,
  .read    = nfs_fuse_read,
  .readdir = nfs_fuse_readdir,
  .rmdir   = nfs_fuse_rmdir,
  .statfs  = nfs_fuse_statfs,
  .unlink  = nfs_fuse_unlink,
  .utimens = nfs_fuse_utimens,
  .write   = nfs_fuse_write,
};

int main(int argc, char* argv[]) {
  log_set_level(LOG_TRACE);
  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
  return fuse_main(args.argc, args.argv, &nfs_fuse_oper, NULL);
}
