#ifndef NFS_FUSE_CLIENT_CACHE_H_
#define NFS_FUSE_CLIENT_CACHE_H_

#include <sys/stat.h>
#include <sys/types.h>

// TODO Create a "redis context" so that you could have multiple redis
// instances. Though technically that isn't really useful to our NFS code.

int init_cache(const char* hostname, int port, size_t chunk_size);
int close_cache();

int clear_cache();
size_t get_chunk_size();

int save_open_flags(const char* path, int open_flags);
int save_stat(const char* path, struct stat sb);
int load_open_flags(const char* path, int* open_flags);
int load_stat(const char* path, struct stat* sb);

int save_metadata(const char* path, int open_flags, struct stat sb);
int load_metadata(const char* path, int* open_flags, struct stat* sb);

// Always save metadata before saving the file - metadata info is used.
int save_file(const char* path, off_t offset, size_t size, const char* in_data);
int load_file(const char* path, off_t offset, size_t size, char* out_data);
int remove_file(const char* path);

#endif /* NFS_FUSE_CLIENT_CACHE_H_ */

