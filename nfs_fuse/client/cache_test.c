#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "cache.h"

int main() {
  init_cache(NULL, 0, 0);
  int ret;
  const char* fpath = "test/a";

  mode_t modet = O_RDONLY;
  int fd = open(fpath, O_RDONLY);
  if (fd == -1) {
    printf("shit\n");
    return -1;
  }
  struct stat sb;
  ret = fstat(fd, &sb);
  if (ret == -1) {
    printf("error stat\n");
    return -1;
  }
  printf("file size: %lu\n", sb.st_size);

  char data[1000];
  read(fd, data, sb.st_size);

  ret = save_metadata(fpath, modet, sb);
  if (ret == -1) {
    printf("error meta\n");
    return -1;
  }

  ret = save_file(fpath, 0, sb.st_size, data);
  if (ret == -1) {
    printf("error file\n");
    return -1;
  }

  mode_t mode_out;
  struct stat sb_out;
  char data_out[10];
  ret = load_metadata(fpath, &mode_out, &sb_out);
  if (ret == -1) {
    printf("shit loading meta\n");
    return -1;
  }

  if (mode_out != modet)
    printf("didn't save mode properly\n");
  if (memcmp(&sb, &sb_out, sizeof(struct stat)) != 0)
    printf("didn't save stat properly\n");

  ret = load_file(fpath, 0, 4096, data_out);
  if (ret == -1) {
    printf("error loading file");
    return -1;
  }

  if (memcmp(data, data_out, sb.st_size) != 0)
    printf("error retrievied data\n");

  return 0;
}
