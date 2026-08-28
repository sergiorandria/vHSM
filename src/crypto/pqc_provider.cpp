#include "pqc_provider.h"

#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

#ifndef _WIN32
#include <dirent.h>
#include <sys/types.h>
#endif

#ifdef VHSM_PQC
#include <oqs/oqs.h>
#endif

namespace vhsm::crypto {

std::string to_string(PqcAlgo a) {
  return a == PqcAlgo::Dilithium3 ? "DILITHIUM3" : "SPHINCS_SHA256";
}

std::optional<PqcAlgo> pqc_algo_from_string(const std::string &s) {
  if (s == "DILITHIUM3")
    return PqcAlgo::Dilithium3;
  if (s == "SPHINCS_SHA256")
    return PqcAlgo::SphincsSha256;
  return std::nullopt;
}

namespace {
#ifdef VHSM_PQC
const char *oqs_alg_name(PqcAlgo a) {
  return a == PqcAlgo::Dilithium3 ? OQS_SIG_alg_dilithium_3
                                  : "SPHINCS+-sha256-128f";
}
#endif
} // namespace

bool PqcProvider::available() {
#ifdef VHSM_PQC
  return true; // built with liboqs; individual alg availability checked per-call
#else
  return false;
#endif
}

std::optional<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
PqcProvider::keypair(PqcAlgo a) {
#ifdef VHSM_PQC
  OQS_SIG *sig = OQS_SIG_new(oqs_alg_name(a));
  if (!sig)
    return std::nullopt;
  std::vector<uint8_t> pk(sig->length_public_key);
  std::vector<uint8_t> sk(sig->length_secret_key);
  if (OQS_SIG_keypair(sig, pk.data(), sk.data()) != OQS_SUCCESS) {
    OQS_SIG_free(sig);
    return std::nullopt;
  }
  OQS_SIG_free(sig);
  return std::make_pair(std::move(pk), std::move(sk));
#else
  (void)a;
  return std::nullopt;
#endif
}

std::optional<std::vector<uint8_t>>
PqcProvider::sign(PqcAlgo a, const std::vector<uint8_t> &msg,
                  const std::vector<uint8_t> &sk) {
#ifdef VHSM_PQC
  OQS_SIG *sig = OQS_SIG_new(oqs_alg_name(a));
  if (!sig)
    return std::nullopt;
  if (sk.size() != sig->length_secret_key) {
    OQS_SIG_free(sig);
    return std::nullopt;
  }
  std::vector<uint8_t> signature(sig->length_signature);
  size_t sig_len = 0;
  if (OQS_SIG_sign(sig, signature.data(), &sig_len, msg.data(), msg.size(),
                   sk.data()) != OQS_SUCCESS) {
    OQS_SIG_free(sig);
    return std::nullopt;
  }
  signature.resize(sig_len);
  OQS_SIG_free(sig);
  return signature;
#else
  (void)a;
  (void)msg;
  (void)sk;
  return std::nullopt;
#endif
}

bool PqcProvider::verify(PqcAlgo a, const std::vector<uint8_t> &msg,
                         const std::vector<uint8_t> &sig,
                         const std::vector<uint8_t> &pk) {
#ifdef VHSM_PQC
  OQS_SIG *s = OQS_SIG_new(oqs_alg_name(a));
  if (!s)
    return false;
  if (pk.size() != s->length_public_key) {
    OQS_SIG_free(s);
    return false;
  }
  bool ok = OQS_SIG_verify(s, msg.data(), msg.size(), sig.data(), sig.size(),
                           pk.data()) == OQS_SUCCESS;
  OQS_SIG_free(s);
  return ok;
#else
  (void)a;
  (void)msg;
  (void)sig;
  (void)pk;
  return false;
#endif
}

PqcKeyring &PqcKeyring::instance() {
  static PqcKeyring s;
  return s;
}

void PqcKeyring::load_from_dir(const std::string &dir) {
  if (dir.empty())
    return;
#ifdef _WIN32
  // Minimal: skip directory enumeration on Windows for now (keys are loaded
  // explicitly via a manifest in production). Best-effort, no-op here.
  (void)dir;
#else
  // Read every <fingerprint>.sk / <fingerprint>.pk pair. The fingerprint is the
  // classical key's fingerprint; the .sk/.pk carry the paired Dilithium3 key.
  auto read_file = [](const std::string &p) -> std::optional<std::vector<uint8_t>> {
    std::ifstream f(p, std::ios::binary);
    if (!f)
      return std::nullopt;
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)),
                                std::istreambuf_iterator<char>());
  };
  // Enumerate directory entries.
  DIR *d = ::opendir(dir.c_str());
  if (!d)
    return;
  struct dirent *e;
  while ((e = ::readdir(d)) != nullptr) {
    std::string name = e->d_name;
    if (name.size() > 3 && name.compare(name.size() - 3, 3, ".sk") == 0) {
      std::string fp = name.substr(0, name.size() - 3);
      auto sk = read_file(dir + "/" + name);
      auto pk = read_file(dir + "/" + fp + ".pk");
      if (sk && pk) {
        std::lock_guard<std::mutex> lk(mu_);
        keys_[fp] = std::make_pair(*sk, *pk);
      }
    }
  }
  ::closedir(d);
#endif
}

bool PqcKeyring::has(const std::string &classical_fp) const {
  std::lock_guard<std::mutex> lk(mu_);
  return keys_.find(classical_fp) != keys_.end();
}

std::optional<std::vector<uint8_t>>
PqcKeyring::secret_key(const std::string &classical_fp) const {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = keys_.find(classical_fp);
  return it == keys_.end() ? std::optional<std::vector<uint8_t>>{}
                           : it->second.first;
}

std::optional<std::vector<uint8_t>>
PqcKeyring::public_key(const std::string &classical_fp) const {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = keys_.find(classical_fp);
  return it == keys_.end() ? std::optional<std::vector<uint8_t>>{}
                           : it->second.second;
}

} // namespace vhsm::crypto
