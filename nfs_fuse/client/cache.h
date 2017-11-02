#ifndef NFS_FUSE_CLIENT_CACHE_H_
#define NFS_FUSE_CLIENT_CACHE_H_

#include <sys/types.h>

// TODO Allow for config
int init_cache();

int save_file(char* path, size_t path_l, off_t offset,
              char* data, size_t size);

#endif /* NFS_FUSE_CLIENT_CACHE_H_ */

