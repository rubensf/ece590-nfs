#include <stdio.h>

#include "cache.h"

int main() {
  init_cache(NULL, 0, 0);

  int ret = save_file("blop", 5, 0, "gaballllll", 10);
  printf("my ret %d\n", ret);

  char data[10];
  load_file("blop", 5, 0, data, 10);

  printf("%s\n", data);

  return 0;
}
