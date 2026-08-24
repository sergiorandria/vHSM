#pragma once
#ifdef VHSM_OPENSSL_SHIM
#else
#include_next <openssl/ecdsa.h>
#endif
