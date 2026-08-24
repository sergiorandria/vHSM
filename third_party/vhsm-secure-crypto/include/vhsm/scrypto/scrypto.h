#pragma once
// Umbrella header — include everything for new code
#include "aes.h"
#include "aes_gcm.h"
#include "constant_time.h"
#include "ec.h"
#include "hash.h"
#include "hmac.h"
#include "kdf.h"
#include "mem.h"
#include "rng.h"
#include "rsa.h"

namespace vhsm::scrypto {
// Library self-test — runs KATs, returns false on failure (aborts if strict)
bool selftest(bool strict = true);
const char *version() noexcept;
} // namespace vhsm::scrypto
