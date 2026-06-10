/*
 * aes_gcm.cpp
 *
 * AES-256-GCM helper implementation using OpenSSL EVP interface.
 * Provides `encrypt` which generates a 12-byte nonce and 16-byte tag,
 * and `decrypt` which verifies the tag and returns the plaintext.
 *
 * Notes:
 * - Keys are expected to be 32 bytes (AES-256).
 * - The implementation uses the high-level EVP_CIPHER_CTX APIs.
 * - Proper error checking and buffer length handling are important; callers
 *   should ensure key lengths are correct and handle exceptions on auth failure.
 */

#include "aes_gcm.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>

// Encrypt: initializes a GCM context, sets IV length, provides the key/nonce,
// then encrypts the plaintext producing ciphertext and the authentication tag.
// The caller receives ciphertext, nonce and tag in AESGCMResult.
AESGCMResult AESGCM::encrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& plaintext)
{
    int len = 0, final_len = 0;
    AESGCMResult result;

    result.nonce.resize(12);
    RAND_bytes(result.nonce.data(), 12);

    result.tag.resize(16);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    // Should check return value, but it's better to 
    // use macro instead of if () { throw(...); }. 
    // This comment will be removed when the macro is defined later.
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, result.nonce.size(), nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), result.nonce.data());

    result.ciphertext.resize(plaintext.size());
    
    EVP_EncryptUpdate(ctx, result.ciphertext.data(), &len, plaintext.data(), plaintext.size());
    EVP_EncryptFinal_ex(ctx, result.ciphertext.data() + len, &final_len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, result.tag.data());
    EVP_CIPHER_CTX_free(ctx);

    return result;
}


// Decrypt: initializes a GCM context, sets IV length and tag, then attempts
// to decrypt and verify the authentication tag. On authentication failure
// a runtime_error is thrown.
std::vector<uint8_t> AESGCM::decrypt(const std::vector<uint8_t>& key, const AESGCMResult& data)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, data.nonce.size(), nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), data.nonce.data());

    int len = 0;
    std::vector<uint8_t> plaintext(data.ciphertext.size());

    EVP_DecryptUpdate(ctx, plaintext.data(), &len, data.ciphertext.data(),data.ciphertext.size());
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)data.tag.data());

    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);

    EVP_CIPHER_CTX_free(ctx);

    if(ret <= 0) {
        throw std::runtime_error(
            "authentication failed");
    }
    
    return plaintext;
}

