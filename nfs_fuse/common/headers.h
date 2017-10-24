#include <stdint.h>

#define NFS_FUSE_REQUEST_DESTROY  0
#define NFS_FUSE_REQUEST_GETATTR  1
#define NFS_FUSE_REQUEST_INIT     2
#define NFS_FUSE_REQUEST_MKDIR    3
#define NFS_FUSE_REQUEST_READ     4
#define NFS_FUSE_REQUEST_READDIR  5
#define NFS_FUSE_REQUEST_RENAME   6
#define NFS_FUSE_REQUEST_RMDIR    7
#define NFS_FUSE_REQUEST_STATFS   8
#define NFS_FUSE_REQUEST_WRITE    9

struct request {
  uint32_t type;
  j
  void* request;
  // This remains last for variable size.
};

struct request_destroy {
  char* path;
}

struct request req;
if (req.type == NFS_FUSE_REQUEST_DESTROY)
