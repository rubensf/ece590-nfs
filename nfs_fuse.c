#define FUSE_USE_VERSION 31

#include <fuse.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sshlib.h"

ssh_session global_ssh;
sftp_session global_sftp;

static void refresh_ssh() {
  if (!ssh_is_connected(global_ssh)) {
    sftp_free(global_sftp);
    ssh_free(global_ssh);
    global_ssh = make_ssh_connection("esa02", "10.148.54.36");
    global_sftp = make_sftp_session(global_ssh);
  }
}

static void *nfs_fuse_init(struct fuse_conn_info *conn,
                           struct fuse_config *cfg){
  cfg->kernel_cache = 0;
  return NULL;
}

static int nfs_fuse_getattr(const char *path,
                            struct stat* stbuf,
                            struct fuse_file_info *fi) {
  printf("DB getattr\n");
  refresh_ssh();
  printf("passed ssh\n");

  memset(stbuf, 0, sizeof(struct stat));
  sftp_attributes attr = sftp_stat(global_sftp, path);
  if (!attr) {
    fprintf(stderr, "Error! Cannot open path %s for read.\n", path);
    return -ENOENT;
  }

  stbuf->st_uid  = attr->uid;
  stbuf->st_gid  = attr->gid;
  stbuf->st_size = attr->size;
  stbuf->st_mode = attr->permissions;
  // TODO Figure out n link?

  sftp_attributes_free(attr);
  return 0;
}

static int nfs_fuse_readdir(const char *path,
                            void *buf, fuse_fill_dir_t filler,
                            off_t offset,
                            struct fuse_file_info *fi,
                            enum fuse_readdir_flags flags) {
  printf("DB readdir\n");
  refresh_ssh();
  printf("passed ssh\n");

  sftp_dir dir = sftp_opendir(global_sftp, path);
  if (!dir) {
    fprintf(stderr, "Error! Cannot open directory %s for read.", path);
    return -ENOENT;
  }

  printf("trying???\n");
  sftp_attributes attr;
  while ((attr = sftp_readdir(global_sftp, dir))) {
    printf("ATTRIBUTE\nATRIBUTEdsa!@#!@#!@#\n%s\n", attr->name);
    filler(buf, attr->name, NULL, 0, 0);
    sftp_attributes_free(attr);
  }

  return 0;
}

static int nfs_fuse_read(const char *path,
                         char *buf,
                         size_t size,
                         off_t offset,
                         struct fuse_file_info *fi) {
  printf("DB read\n");
  refresh_ssh();
  printf("passed ssh\n");

  int access_type = O_RDONLY;
  sftp_file file = sftp_open(global_sftp, path, access_type, 0);
  if (!file) {
    fprintf(stderr, "Error! Cannot open file %s for read. %d", path, -ENOENT);
    return -ENOENT;
  }

  sftp_attributes attr = sftp_fstat(file);
  size_t file_size = attr->size;
  if (offset < file_size) {
    if (offset + size > file_size) {
      size = file_size - offset;
    }
    sftp_read(file, buf, size);
  } else
    size = 0;

  sftp_attributes_free(attr);
  sftp_close(file);
  return size;
}

static struct fuse_operations nfs_fuse_oper = {
  .init    = nfs_fuse_init,
  .getattr = nfs_fuse_getattr,
  .readdir = nfs_fuse_readdir,
  .read    = nfs_fuse_read,
};

int main(int argc, char* argv[]) {
  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
  refresh_ssh();
  return fuse_main(args.argc, args.argv, &nfs_fuse_oper, NULL);
}
