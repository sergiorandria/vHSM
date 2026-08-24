#pragma once
#ifdef VHSM_OPENSSL_SHIM
#include "openssl/crypto.h"
#else
#include_next <openssl/ssl.h>
#endif
