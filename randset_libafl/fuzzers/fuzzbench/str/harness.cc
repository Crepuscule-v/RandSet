extern "C" {
#include <libstr/str.h>
}

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  CheckStr(reinterpret_cast<const char *>(data));
  CheckStrv2(reinterpret_cast<const char *>(data));
  return 0;
}
