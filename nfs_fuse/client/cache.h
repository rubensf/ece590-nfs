#ifndef NFS_FUSE_CLIENT_CACHE_H_
#define NFS_FUSE_CLIENT_CACHE_H_

#include <sys/types.h>

int init_cache(const char* hostname, int port, size_t chunk_size);

int clear_cache();

// No need for a save_last_modify because we should only be saving
// that on a save file.
int load_last_modify(char* path, size_t path_l, off_t offset,
                     struct timespec* out);

int save_file(char* path, size_t path_l, off_t offset,
              char* in_data, size_t size, struct timespec last_m);

int load_file(char* path, size_t path_l, off_t offset,
              char* out_data, size_t size);

#endif /* NFS_FUSE_CLIENT_CACHE_H_ */

