#pragma once
#ifdef VHSM_OPENSSL_SHIM
typedef struct buf_mem_st {
  size_t length;
  char *data;
} BUF_MEM;
#else
#include_next <openssl/buffer.h>
#endif
