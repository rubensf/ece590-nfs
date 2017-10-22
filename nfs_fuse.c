#define FUSE_USE_VERSION 31

#include <fuse.h>

#include <stdio.h>
#include <stdlib.h>

#include "sshlib.c"

static void *nfs_fuse_init(struct fuse_conn_info *conn,
                           struct fuse_config *cfg){
  (void) conn;
  cfg->kernel_cache = 0;
  return NULL;
}

static int nfs_fuse_read(const char *path,
                         char *buf,
                         size_t size,
                         off_t offset,
                         struct fuse_file_info *fi) {

  return 0;
}

static struct fuse_operations nfs_fuse_oper = {
  .init    = nfs_fuse_init,
  .read    = nfs_fuse_read,
};

int main(int argc, char* argv[]) {
  ssh_session ssh_sess = make_ssh_connection("esa02", "10.148.54.36");
}
