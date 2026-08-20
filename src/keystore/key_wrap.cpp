#include "key_wrap.h"
#include "../core/error.h"
#include "../crypto/aes_ecb.h"

#include <cstring>
#include <openssl/crypto.h>
#include <sys/mman.h>

namespace vhsm::keystore {

KeyWrap::KeyWrap(const std::vector<u8> &master_kek) {
  VHSM_CHECK_MSG(
      master_kek.size() == 32,
      "KeyWrap Initialization Error: KEK must be exactly 32 bytes for AES-256");

  // WHY copy KEK into internal_kek: We don't hold the caller's buffer; we own
  // a copy so we can apply security controls (mlock) without affecting their
  // memory.
  internal_kek = master_kek;

  // WHY mlock: Prevent the OS from swapping the KEK to disk. If the system is
  // compromised and the disk is forensically analyzed, the KEK won't be found
  // in swap files. This is defense-in-depth: even if memory is dumped, the
  // attacker can't recover keys if we've locked them in RAM.
  mlock(internal_kek.data(), internal_kek.size());
}

KeyWrap::~KeyWrap() {
  // WHY explicit destroy: The KEK is sensitive and must not linger in memory
  // after the destructor. OPENSSL_cleanse overwrites with zeros using a method
  // the compiler can't optimize away. Then munlock releases the page lock.
  if (!internal_kek.empty()) {
    // WHY OPENSSL_cleanse first: Before unlocking, overwrite the memory.
    // If we munlock first, the OS could swap the key to disk before cleanse
    // runs.
    OPENSSL_cleanse(internal_kek.data(), internal_kek.size());
    munlock(internal_kek.data(), internal_kek.size());
  }
}

std::vector<u8> KeyWrap::wrap(const std::vector<u8> &plaintext_key) const {
  VHSM_CHECK_MSG(
      plaintext_key.size() >= 16 && plaintext_key.size() % 8 == 0,
      "Plaintext key size must be a multiple of 8 bytes and >= 16 bytes");

  // WHY n = size/8: RFC 3394 operates on semi-blocks (8-byte units).
  // We convert the plaintext size to the number of 8-byte blocks (n).
  size_t n = plaintext_key.size() / 8;

  // WHY result is (n+1)*8: The output is the 64-bit ICV (1 semi-block) plus
  // the n semi-blocks of encrypted key material. Total: (n+1) semi-blocks.
  std::vector<u8> result((n + 1) * 8);

  // WHY mlock result: The result vector holds the wrapped key, which is still
  // sensitive (it's encrypted with the KEK). If the OS swaps it, an attacker
  // could potentially recover both the wrapped key and the KEK from disk
  // analysis.
  mlock(result.data(), result.size());

  // WHY A = AIV: Start with the recommended IV from RFC 3394.
  u64 A = AIV;

  // WHY copy plaintext into result starting at offset 8: The result layout is:
  // [8 bytes ICV] [n*8 bytes key data]
  // We keep the first 8 bytes for the ICV and fill the rest with the plaintext.
  std::memcpy(result.data() + 8, plaintext_key.data(), plaintext_key.size());

  uint8_t block[16];
  // WHY 6 rounds (j=0..5): RFC 3394 specifies 6 rounds for all key sizes.
  // This provides semantic security against known-plaintext attacks.
  for (size_t j = 0; j <= 5; ++j) {
    // WHY iterate i=1..n: For each round, process each of the n semi-blocks.
    // i=1 means the first semi-block; PKCS#11 uses 1-based indexing.
    for (size_t i = 1; i <= n; ++i) {
      // WHY concatenate A||R[i]: RFC 3394 AES-ECB wraps by encrypting
      // the concatenation of the current ICV and a semi-block.
      std::memcpy(block, &A, 8);
      std::memcpy(block + 8, result.data() + (i * 8), 8);

      // WHY isolated AES-ECB block cipher: This module provides a clean
      // separation of concerns. Cryptographic primitives are delegated to
      // crypto/aes_ecb.h; keystore doesn't implement AES directly.
      crypto::AESECB::encrypt_block(internal_kek.data(), block, block);

      // WHY t = n*j + i: RFC 3394 embeds a counter into the ICV for each
      // block processed. This counter prevents attacks that reorder blocks.
      u64 t = (n * j) + i;

      // WHY memcpy(&A, block, 8): Extract the encrypted ICV (first 8 bytes).
      std::memcpy(&A, block, 8);

      // WHY A ^= t_be: XOR the counter (t) into the ICV. The byte-swap
      // (t_be) ensures we use big-endian (standard in cryptography).
      u64 t_be = __builtin_bswap64(t);
      A ^= t_be;

      // WHY memcpy back to result: Store the encrypted semi-block for the next
      // round.
      std::memcpy(result.data() + (i * 8), block + 8, 8);
    }
  }

  // WHY store A at result[0]: The final ICV goes at the beginning.
  std::memcpy(result.data(), &A, 8);

  // WHY wipe temporary block: Don't leave the plaintext block in stack memory.
  OPENSSL_cleanse(block, sizeof(block));
  munlock(result.data(), result.size());

  return result;
}

std::vector<u8> KeyWrap::unwrap(const std::vector<u8> &ciphertext_key) const {
  VHSM_CHECK_MSG(
      ciphertext_key.size() >= 24 && ciphertext_key.size() % 8 == 0,
      "Ciphertext key size must be a multiple of 8 bytes and >= 24 bytes");

  // WHY n = (size/8) - 1: The ciphertext is (n+1) semi-blocks: 1 for ICV + n
  // for data. Subtract 1 to recover n (the number of data semi-blocks).
  size_t n = (ciphertext_key.size() / 8) - 1;

  // WHY allocate n*8 bytes: The unwrapped key is the data portion (without the
  // ICV).
  std::vector<u8> result(n * 8);

  mlock(result.data(), result.size());

  // WHY memcpy first 8 bytes to A: Extract the ICV from the wrapped key.
  u64 A;
  std::memcpy(&A, ciphertext_key.data(), 8);

  // WHY copy remaining bytes: Extract the encrypted data semi-blocks.
  std::memcpy(result.data(), ciphertext_key.data() + 8, result.size());

  uint8_t block[16];
  // WHY j counts backward (5 down to 0): RFC 3394 unwrap reverses the wrap
  // process. We undo the 6 rounds in reverse order.
  for (ssize_t j = 5; j >= 0; --j) {
    // WHY i counts backward (n down to 1): Within each round, process blocks
    // in reverse order (right-to-left) to properly invert the wrap algorithm.
    for (ssize_t i = n; i >= 1; --i) {
      // WHY calculate t and XOR before decrypt: We must undo the counter
      // embedding before decryption to recover the original ICV.
      u64 t = (n * j) + i;
      u64 t_be = __builtin_bswap64(t);

      A ^= t_be;

      // WHY concatenate A||R[i-1] for decryption: Reverse the wrap algorithm.
      // We decrypt the block to get the original A and semi-block.
      std::memcpy(block, &A, 8);
      std::memcpy(block + 8, result.data() + ((i - 1) * 8), 8);

      // WHY call decrypt_block: We encrypt during wrap, so we decrypt during
      // unwrap.
      crypto::AESECB::decrypt_block(internal_kek.data(), block, block);

      // WHY extract A and store semi-block back: The decrypted block's first
      // 8 bytes are the (incrementally updated) ICV; the last 8 are the
      // original data.
      std::memcpy(&A, block, 8);
      std::memcpy(result.data() + ((i - 1) * 8), block + 8, 8);
    }
  }

  // WHY verify A == AIV: If unwrap succeeded, the ICV must match the expected
  // value. This is the integrity check. If A != AIV, the key was corrupted or
  // decrypted with the wrong KEK, and we REJECT (fail-closed).
  if (A != AIV) {
    // WHY cleanse before throwing: If integrity check fails, wipe the
    // partially-unwrapped key from memory before propagating the error.
    // This prevents a corrupted key from being used or leaked.
    OPENSSL_cleanse(result.data(), result.size());
    OPENSSL_cleanse(block, sizeof(block));
    munlock(result.data(), result.size());
    throw std::runtime_error(
        "CRITICAL SECURITY ERROR: Integrity verification failed.");
  }

  // WHY wipe temporary block: Don't leave plaintext in the stack.
  OPENSSL_cleanse(block, sizeof(block));
  munlock(result.data(), result.size());

  return result;
}
} // namespace vhsm::keystore