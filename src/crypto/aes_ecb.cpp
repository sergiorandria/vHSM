#include "aes_ecb.h"
#include <openssl/evp.h>

namespace vhsm::crypto
{

void AESECB::encrypt_block(const uint8_t* key, const uint8_t* input, uint8_t* output)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        throw std::runtime_error("AES-ECB Error: Context allocation failure");
    }

    int len;
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, key, nullptr)
        || 1 != EVP_CIPHER_CTX_set_padding(ctx, 0) || 1 != EVP_EncryptUpdate(ctx, output, &len, input, 16))
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-ECB Error: Hardware encryption instruction failed");
    }
    EVP_CIPHER_CTX_free(ctx);
}

void AESECB::decrypt_block(const uint8_t* key, const uint8_t* input, uint8_t* output)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        throw std::runtime_error("AES-ECB Error: Context allocation failure");
    }

    int len;
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, key, nullptr)
        || 1 != EVP_CIPHER_CTX_set_padding(ctx, 0) || 1 != EVP_DecryptUpdate(ctx, output, &len, input, 16))
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-ECB Error: Hardware decryption instruction failed");
    }
    EVP_CIPHER_CTX_free(ctx);
}
} // namespace vhsm::crypto