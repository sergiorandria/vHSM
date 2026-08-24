#pragma once
#ifdef VHSM_OPENSSL_SHIM
#define OSSL_PKEY_PARAM_RSA_N "n"
#else
#include_next <openssl/core_names.h>
#endif
