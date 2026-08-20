#ifndef vHSM_KEY_WRAP_H
#define vHSM_KEY_WRAP_H

#include "../core/types.h"
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace vhsm::keystore {

/**
 * @brief RFC 3394 AES Key Wrap library container.
 * Manages structural orchestration and integrity verification using AESECB.
 *
 * WHY encapsulate RFC 3394: Key wrapping protects keys at rest. Unlike
 * encryption (which obscures plaintext), wrapping is designed specifically for
 * key material: it adds a 64-bit integrity check value (ICV) that detects
 * tampering. If the ICV doesn't match on unwrap, we know the key was corrupted
 * or malicious.
 *
 * WHY AESECB (not AESCBC, AESCTR): RFC 3394 is defined with ECB mode to ensure
 * deterministic output (same plaintext → same ciphertext). This is intentional
 * for key wrapping; it lets us verify integrity without storing a separate IV.
 */
class KeyWrap {
public:
  /**
   * @brief Constructor that initializes the library with a specific KEK.
   * @param master_key The 32-byte (256-bit) Key Encryption Key.
   *
   * WHY require exactly 32 bytes: AES-256 demands a 256-bit (32-byte) key.
   * Accepting smaller would weaken security. Rejecting mismatches at
   * construction prevents accidental use of weak keys or misunderstanding the
   * API contract.
   */
  explicit KeyWrap(const std::vector<u8> &master_key);

  /**
   * @brief Destructor designed to securely erase the internal KEK from RAM.
   *
   * WHY explicit wipe in destructor: The KEK must never persist after the
   * KeyWrap is destroyed. Using OPENSSL_cleanse + munlock ensures the OS
   * can't swap the key to disk, and the memory is zeroed before deallocation.
   */
  ~KeyWrap();

  // WHY delete copy (not just private): Copy would duplicate the KEK in memory,
  // doubling the attack surface. Delete makes it a compile-time error (caught
  // immediately in code review). Move is OK because it leaves the source empty.
  KeyWrap(const KeyWrap &) = delete;
  KeyWrap &operator=(const KeyWrap &) = delete;
  KeyWrap(KeyWrap &&) noexcept = default;
  KeyWrap &operator=(KeyWrap &&) noexcept = default;

  /**
   * @brief Encapsulates a target plaintext key using the internal KEK via RFC
   * 3394.
   * @param plaintext_key Key to protect (size must be a multiple of 8 bytes,
   * min 16 bytes).
   * @return Wrapped ciphertext vector (+8 bytes overhead).
   *
   * WHY require multiple of 8 bytes: RFC 3394 operates on 64-bit blocks. Keys
   * must be multiples of 8 to fit evenly into blocks. Minimum 16 bytes (2
   * blocks) ensures the wrapped output is > 8 bytes, avoiding collision with
   * empty keys.
   *
   * WHY +8 bytes overhead: The ICV (Initialization Check Value) is 64 bits.
   * It's prepended to the wrapped output, so wrapped_size = plaintext_size + 8.
   */
  std::vector<u8> wrap(const std::vector<u8> &plaintext_key) const;

  /**
   * @brief Decapsulates a wrapped key and validates the 6-round integrity
   * matrix.
   * @param ciphertext_key Wrapped data starting with the 64-bit integrity
   * register.
   * @return Decrypted raw key vector.
   * @throws std::runtime_error If verification fails.
   *
   * WHY "6-round integrity matrix": RFC 3394 performs 6 rounds (3 forward, 3
   * backward) of XOR and encryption. This is the standard, proven to be secure
   * against known-plaintext attacks. The integrity check embedded in the ICV is
   * verified at the end—if it doesn't match, the key was tampered with and we
   * REJECT.
   *
   * WHY throw on mismatch: A mismatched ICV is a cryptographic failure
   * (attacker tamper or corruption). We fail-closed: reject the key immediately
   * rather than returning a corrupted key to the caller.
   */
  std::vector<u8> unwrap(const std::vector<u8> &ciphertext_key) const;

private:
  // WHY non-const internal_kek: We call mlock() on it in the constructor,
  // which requires non-const. mlock() locks the memory pages in RAM so the OS
  // can't swap them to disk (protecting the KEK from forensic recovery).
  std::vector<u8> internal_kek;

  // WHY AIV = 0xA6A6A6A6A6A6A6A6: This is the standard "Recommended IV" from
  // RFC 3394 for standard key wrap (not alternative). All implementations use
  // this magic constant. It serves as a sanity check: if the unwrapped ICV
  // matches, we know the key wasn't corrupted or decrypted with the wrong KEK.
  static const uint64_t AIV = 0xA6A6A6A6A6A6A6A6;
};

} // namespace vhsm::keystore

#endif // vHSM_KEY_WRAP_H