#ifndef VHSM_CRYPTO_PQC_H
#define VHSM_CRYPTO_PQC_H

#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace vhsm::crypto {

// Post-quantum signature algorithms supported for hybrid (classical + PQC)
// signing. Dilithium3 is the primary hedge; SPHINCS+ (SHA-256, 128f) is the
// stateless hash-based backup.
enum class PqcAlgo { Dilithium3, SphincsSha256 };

std::string to_string(PqcAlgo a);
std::optional<PqcAlgo> pqc_algo_from_string(const std::string &s);

// Opaque PQC signing provider. The real Dilithium/SPHINCS+ implementation is
// compiled only when VHSM_PQC=ON and liboqs is present; otherwise available()
// returns false and every operation fails closed, so the classical ECDSA/RSA
// path keeps working unchanged.
class PqcProvider {
public:
  static bool available();

  // Returns (public_key, secret_key) raw bytes, or nullopt on failure.
  static std::optional<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
  keypair(PqcAlgo a);

  // Sign `msg` with `sk`; returns the raw signature, or nullopt on failure.
  static std::optional<std::vector<uint8_t>>
  sign(PqcAlgo a, const std::vector<uint8_t> &msg,
       const std::vector<uint8_t> &sk);

  // Verify `sig` over `msg` against `pk`.
  static bool verify(PqcAlgo a, const std::vector<uint8_t> &msg,
                     const std::vector<uint8_t> &sig,
                     const std::vector<uint8_t> &pk);
};

// Maps a classical key fingerprint to its paired PQC key (Dilithium3) so each
// classical sign also produces a post-quantum signature. Loaded once at startup
// from a directory of <fingerprint>.sk / <fingerprint>.pk raw-key files
// (VHSM_PQC_KEYRING_DIR).
class PqcKeyring {
public:
  static PqcKeyring &instance();

  // Load <dir>/<fingerprint>.sk and <dir>/<fingerprint>.pk (raw bytes). Missing
  // files are ignored; only successfully parsed keys are registered.
  void load_from_dir(const std::string &dir);

  bool has(const std::string &classical_fp) const;
  std::optional<std::vector<uint8_t>> secret_key(const std::string &classical_fp) const;
  std::optional<std::vector<uint8_t>> public_key(const std::string &classical_fp) const;

private:
  PqcKeyring() = default;
  mutable std::mutex mu_;
  std::unordered_map<std::string, std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
      keys_; // fp -> (sk, pk)
};

} // namespace vhsm::crypto

#endif // VHSM_CRYPTO_PQC_H
