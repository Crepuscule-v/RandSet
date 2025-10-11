#include "str.h"

#include <stdlib.h>

void CheckStr(const char *str) {
  if (strncmp(str, "fuzz", 4) == 0) {
    abort();
  }

  if (str[0] == 'b' && str[1] == 'a' && str[2] == 'd') {
    abort();
  }

  return;
}

void CheckStrv2(const char *str) {
  if (str[0] == 'B' && str[1] == 'A' && str[2] == 'D') {
    abort();
  }
  // OK
}

#ifdef STAND_ALONE
int main() {
  return 0;
}
#endif
