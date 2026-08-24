#pragma once
#ifdef VHSM_OPENSSL_SHIM
typedef void BIGNUM;
#else
#include_next <openssl/bn.h>
#endif
