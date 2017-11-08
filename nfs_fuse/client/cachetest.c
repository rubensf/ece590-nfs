#include <stdio.h>

#include "cache.h"

int main() {
  init_cache(NULL, 0, 0);

  int ret = save_file("blop", 5, 0, "gaballllll", 10);
  printf("my ret %d\n", ret);


  return 0;
}
