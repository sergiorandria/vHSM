#include "kdf.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>

#include <cstring>
#include <stdexcept>

#include "../core/error.h"
#include "../core/macros.h"

// PBKDF2 implementation notes: We use OpenSSL's PKCS5_PBKDF2_HMAC directly
// rather than the generic EVP_KDF API.  PKCS5_PBKDF2_HMAC is a stable C helper
// that needs no per-call context construction/destruction and is thread-safe
// (each invocation creates its own internal state).  The salt and password are
// passed as raw bytes; the caller is responsible for not logging them.
std::vector<u8> vhsm::persistence::derive_vault_key(
    const std::string& password,
    const std::vector<u8>& salt,
    std::uint32_t iterations,
    std::size_t out_len)
{
    VHSM_CHECK_MSG(!password.empty(), "derive_vault_key: password must not be empty");
    VHSM_CHECK_MSG(!salt.empty(), "derive_vault_key: salt must not be empty");
    VHSM_CHECK_MSG(iterations > 0, "derive_vault_key: iterations must be > 0");
    VHSM_CHECK_MSG(out_len > 0, "derive_vault_key: out_len must be > 0");

    std::vector<u8> out(out_len);
    const int rc = PKCS5_PBKDF2_HMAC(
        password.data(),
        static_cast<int>(password.size()),
        salt.data(), static_cast<int>(salt.size()),
        static_cast<int>(iterations),
        EVP_sha256(),
        static_cast<int>(out_len),
        out.data());
    VHSM_CHECK_MSG(rc == 1, "derive_vault_key: PKCS5_PBKDF2_HMAC failed");

    return out;
}

// HKDF-SHA256 per RFC 5869.  We implement Extract+Expand manually with HMAC so
// the code has no hidden dependency on an EVP_KDF provider being registered
// (some OpenSSL 3.x minimal builds omit the HKDF provider by default).
//
// Extract: PRK = HMAC-SHA256(salt, IKM)
// Expand:  T(i) = HMAC-SHA256(PRK, T(i-1) || info || i), for i = 1..N
std::vector<u8> vhsm::persistence::hkdf_sha256(
    const std::vector<u8>& ikm,
    const std::vector<u8>& salt,
    const std::vector<u8>& info,
    std::size_t out_len)
{
    VHSM_CHECK_MSG(!ikm.empty(), "hkdf_sha256: IKM must not be empty");
    VHSM_CHECK_MSG(out_len > 0, "hkdf_sha256: out_len must be > 0");

    constexpr std::size_t kHashLen = 32; // SHA-256 output length

    // ----- Extract -----
    std::vector<u8> salt_effective = salt;
    if (salt_effective.empty()) {
        salt_effective.assign(kHashLen, 0);
    }
    std::vector<u8> prk(kHashLen);
    unsigned int prk_len = 0;
    const bool ok = HMAC(EVP_sha256(),
                         salt_effective.data(), static_cast<int>(salt_effective.size()),
                         ikm.data(), ikm.size(),
                         prk.data(), &prk_len) != nullptr;
    VHSM_CHECK_MSG(ok, "hkdf_sha256: HMAC(Extract) failed");
    VHSM_CHECK_MSG(prk_len == kHashLen, "hkdf_sha256: unexpected PRK length");
    prk.resize(prk_len);

    // ----- Expand -----
    const std::size_t n_blocks = (out_len + kHashLen - 1) / kHashLen;
    std::vector<u8> out;
    out.reserve(n_blocks * kHashLen);

    std::vector<u8> t_prev; // previous T block (empty for i=1)
    std::uint32_t remaining = static_cast<std::uint32_t>(n_blocks);
    for (std::uint8_t i = 1; remaining > 0; ++i, --remaining) {
        std::vector<u8> input;
        input.reserve(t_prev.size() + info.size() + 1);
        input.insert(input.end(), t_prev.begin(), t_prev.end());
        input.insert(input.end(), info.begin(), info.end());
        input.push_back(i);

        std::vector<u8> block(kHashLen);
        unsigned int block_len = 0;
        const bool ok2 = HMAC(EVP_sha256(),
                              prk.data(), static_cast<int>(prk.size()),
                              input.data(), input.size(),
                              block.data(), &block_len) != nullptr;
        VHSM_CHECK_MSG(ok2, "hkdf_sha256: HMAC(Expand) failed");
        VHSM_CHECK_MSG(block_len == kHashLen, "hkdf_sha256: unexpected block length");
        block.resize(block_len);

        out.insert(out.end(), block.begin(), block.end());
        t_prev = std::move(block);
    }

    out.resize(out_len);
    return out;
}

// The DB HMAC key is derived from the vault KEK with a fixed info string so it
// is stable across process restarts (the vault KEK does not change).  The salt
// is intentionally fixed to a constant: HKDF output depends on the input key
// material (the KEK, which is already random), so a random salt would only
// force the key to change whenever the vault was rewritten — exactly what we do
// not want.
std::vector<u8> vhsm::persistence::derive_db_hmac_key(const std::vector<u8>& vault_kek)
{
    static const std::vector<u8> kInfo = {'v', 'H', 'S', 'M', '-', 'd', 'b', '-', 'h', 'm', 'a', 'c'};
    return hkdf_sha256(vault_kek, {}, kInfo, 32);
}

// Explicit instantiations are unnecessary (all helpers are plain functions).
// End of translation unit.