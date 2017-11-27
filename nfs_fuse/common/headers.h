#ifndef NFS_FUSE_HEADERS_H_
#define NFS_FUSE_HEADERS_H_

#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>

#define NFS_FUSE_REQUEST_CREATE    1
#define NFS_FUSE_REQUEST_CHMOD     2
#define NFS_FUSE_REQUEST_CHOWN     3
#define NFS_FUSE_REQUEST_DESTROY   4
#define NFS_FUSE_REQUEST_GETATTR   5
#define NFS_FUSE_REQUEST_INIT      6
#define NFS_FUSE_REQUEST_MKDIR     7
#define NFS_FUSE_REQUEST_OPEN      8
#define NFS_FUSE_REQUEST_READ      9
#define NFS_FUSE_REQUEST_READDIR  10
#define NFS_FUSE_REQUEST_RELEASE  11
#define NFS_FUSE_REQUEST_RENAME   12
#define NFS_FUSE_REQUEST_RMDIR    13
#define NFS_FUSE_REQUEST_STATVFS  14
#define NFS_FUSE_REQUEST_TRUNCATE 15
#define NFS_FUSE_REQUEST_UNLINK   16
#define NFS_FUSE_REQUEST_UTIMENS  17
#define NFS_FUSE_REQUEST_WRITE    18

struct request {
  uint32_t type;
  uint32_t path_l;
  char     path[0];
};

struct request_create {
  mode_t   mode;
};

struct request_chmod {
  mode_t   mode;
};

struct request_chown {
  uid_t    uid;
  gid_t    gid;
};

struct request_mkdir {
  mode_t   mode;
};

struct request_open {
  int      flags;
};

struct request_read {
  size_t   size;
  off_t    offset;
};

struct request_truncate {
  off_t    offset;
};

struct request_write {
  size_t   size;
  off_t    offset;
  char     data[0];
};

typedef struct request          request_t;
typedef struct request_create   request_create_t;
typedef struct request_chmod    request_chmod_t;
typedef struct request_chown    request_chown_t;
typedef struct request_mkdir    request_mkdir_t;
typedef struct request_open     request_open_t;
typedef struct request_read     request_read_t;
typedef struct request_truncate request_truncate_t;
typedef struct request_write    request_write_t;

struct response_create {
  int         ret;
  struct stat sb;
};

struct response_chmod {
  int         ret;
  struct stat sb;
};

struct response_chown {
  int         ret;
  struct stat sb;
};

struct response_getattr {
  int         ret;
  struct stat sb;
};

struct response_open {
  int         ret;
  struct stat sb;
};

struct response_read {
  int    ret;
  struct timespec stamp;
  size_t size;
  char   data[0];
};

struct response_readdir_entry {
  struct stat sb;
  size_t name_l;
  char   name[0];
};

struct response_readdir {
  int    ret;
  size_t size;
  // Should be array of response_readdir_entry.
  char   data[0];
};

struct response_statvfs {
  int            ret;
  struct statvfs sb;
};

struct response_truncate {
  int         ret;
  struct stat sb;
};

struct response_utimens {
  int         ret;
  struct stat sb;
};

struct response_write {
  int         ret;
  size_t      size;
  struct stat sb;
};

typedef struct response_create        response_create_t;
typedef struct response_chmod         response_chmod_t;
typedef struct response_chmod         response_chown_t;
typedef struct response_getattr       response_getattr_t;
typedef struct response_open          response_open_t;
typedef struct response_read          response_read_t;
typedef struct response_readdir_entry response_readdir_entry_t;
typedef struct response_readdir       response_readdir_t;
typedef struct response_statvfs       response_statvfs_t;
typedef struct response_truncate      response_truncate_t;
typedef struct response_utimens       response_utimens_t;
typedef struct response_write         response_write_t;

#endif /* NFS_FUSE_HEADERS_H_ */
