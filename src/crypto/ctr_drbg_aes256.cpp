#include "ctr_drbg_aes256.h"
#include "../core/error.h"
#include "CipherCtxGuard.h"
#include "SecureRNG.h"

#include <cstring>
#include <fstream>
#include <openssl/evp.h>

namespace vhsm::crypto
{
void CTR_DRBG_AES256::increment_v()
{
    for (int i = 15; i >= 0; --i)
    {
        if (++V[i] != 0)
        {
            break;
        }
    }
}

void CTR_DRBG_AES256::aes256_encrypt_block(const std::vector<u8>& input, std::vector<u8>& output)
{
    int len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    VHSM_CHECK_PTR_MSG(ctx != nullptr, "RNG Internal Error: Context creation failed");

    CipherCtxGuard guard(ctx);

    VHSM_CHECK(EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, key.data(), nullptr));
    VHSM_CHECK(EVP_CIPHER_CTX_set_padding(ctx, 0));
    VHSM_CHECK(EVP_EncryptUpdate(ctx, output.data(), &len, input.data(), 16));
}

void CTR_DRBG_AES256::update(const std::vector<u8>& provided_data)
{
    std::vector<u8> temp(48, 0);
    std::vector<u8> output_block(16, 0);

    for (size_t i = 0; i < 3; ++i)
    {
        increment_v();
        aes256_encrypt_block(V, output_block);
        std::memcpy(temp.data() + (i * 16), output_block.data(), 16);
    }

    if (!provided_data.empty() && provided_data.size() == 48)
    {
        for (size_t i = 0; i < 48; ++i)
        {
            temp[i] ^= provided_data[i];
        }
    }

    std::memcpy(key.data(), temp.data(), 32);
    std::memcpy(V.data(), temp.data() + 32, 16);
    OPENSSL_cleanse(temp.data(), temp.size());
}

CTR_DRBG_AES256::CTR_DRBG_AES256(const std::vector<u8>& entropy_input)
{
    if (entropy_input.size() != 48)
    {
        throw std::invalid_argument("Seed must be 48 bytes");
    }

    key.assign(32, 0);
    V.assign(16, 0);
    reseed_counter = 1;
    update(entropy_input);
}

void CTR_DRBG_AES256::reseed(const std::vector<u8>& entropy_input)
{
    if (entropy_input.size() != 48)
    {
        throw std::invalid_argument("Seed must be 48 bytes");
    }

    update(entropy_input);
    reseed_counter = 1;
}

std::vector<u8> CTR_DRBG_AES256::generate(size_t requested_bytes)
{
    if (reseed_counter > RESEED_INTERVAL)
    {
        throw std::runtime_error("Reseed threshold reached");
    }

    std::vector<u8> pseudo_random_bits;
    std::vector<u8> output_block(16, 0);

    while (pseudo_random_bits.size() < requested_bytes)
    {
        increment_v();
        aes256_encrypt_block(V, output_block);
        pseudo_random_bits.insert(pseudo_random_bits.end(), output_block.begin(), output_block.end());
    }

    pseudo_random_bits.resize(requested_bytes);
    update(std::vector<u8>()); // Enforce Forward Security
    reseed_counter++;

    return pseudo_random_bits;
}

CTR_DRBG_AES256::~CTR_DRBG_AES256()
{
    OPENSSL_cleanse(key.data(), key.size());
    OPENSSL_cleanse(V.data(), V.size());
}

std::vector<u8> SecureRNG::get_system_entropy(const std::string& source_path)
{
    std::vector<u8> entropy(48);
    std::ifstream source(source_path, std::ios::in | std::ios::binary);

    if (!source || !source.read(reinterpret_cast<char*>(entropy.data()), 48))
    {
        throw std::runtime_error("RNG Failure: Enclave cannot reach system entropy source: " + source_path);
    }

    return entropy;
}
} // namespace vhsm::crypto