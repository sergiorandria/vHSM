#ifndef VHSM_CRYPTO_FIPS_H
#define VHSM_CRYPTO_FIPS_H

#include <string>

namespace vhsm::crypto {

// FIPS 140-3 operating mode. Enabled by the VHSM_FIPS environment variable
// (1/true/yes). In FIPS mode only approved mechanisms may be used and the
// daemon runs a known-answer self-test at startup, refusing to operate if any
// KAT fails.
bool fips_mode();

// True if `mech` (a PKCS#11 CK_MECHANISM_TYPE value) is allowed under FIPS
// mode. Non-approved mechanisms return CKR_MECHANISM_INVALID from sign/encrypt.
bool mechanism_approved(unsigned long mech);

// Run known-answer self-tests (SHA-256, AES-256-GCM, ECDSA P-256 sign/verify).
// Returns true when every KAT passes. Call once at startup when fips_mode().
bool fips_self_test();

} // namespace vhsm::crypto

#endif // VHSM_CRYPTO_FIPS_H
