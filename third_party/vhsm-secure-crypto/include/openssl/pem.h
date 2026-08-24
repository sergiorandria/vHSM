#pragma once
#ifdef VHSM_OPENSSL_SHIM
typedef void pem_password_cb;
#else
#include_next <openssl/pem.h>
#endif
