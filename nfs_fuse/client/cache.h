#ifndef NFS_FUSE_CLIENT_CACHE_H_
#define NFS_FUSE_CLIENT_CACHE_H_

#include <sys/stat.h>
#include <sys/types.h>

int init_cache(const char* hostname, int port, size_t chunk_size);

int clear_cache();
size_t get_chunk_size();

int save_metadata(const char* path, int open_flags, struct stat sb);
int load_metadata(const char* path, int* open_flags, struct stat* sb);

// Always save metadata before saving the file - metadata info is used.
int save_file(const char* path, off_t offset, size_t size, const char* in_data);
int load_file(const char* path, off_t offset, size_t size, char* out_data);
int remove_file(const char* path);

#endif /* NFS_FUSE_CLIENT_CACHE_H_ */

