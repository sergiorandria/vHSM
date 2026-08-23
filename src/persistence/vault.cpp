#include "vault.h"

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <io.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

#include <atomic>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <stdexcept>

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include "../core/error.h"
#include "../core/macros.h"
#include "../crypto/aes_gcm.h"
#include "kdf.h"
#include "le_bytes.h"
#include "vault_format.h"

// Vault I/O layering: The class reads/writes the raw file bytes itself (using
// POSIX open/read/write/fsync) and delegates the actual encryption to
// crypto::AESGCM plus the key derivation to persistence::derive_vault_key.
// Keeping the byte-level marshalling here means the crypto module sees only
// simple byte vectors and never touches files — a clean separation of concerns.

namespace vhsm::persistence {

std::vector<std::uint8_t> read_file_bytes(const std::filesystem::path &p) {
  std::ifstream f(p, std::ios::binary);
  if (!f) {
    throw std::runtime_error("Vault: cannot open file: " + p.string());
  }
  return std::vector<std::uint8_t>((std::istreambuf_iterator<char>(f)),
                                   std::istreambuf_iterator<char>());
}

std::uint32_t Vault::version() const noexcept { return version_; }

// Internal: derive a KEK from the stored password and the header's salt.
std::vector<u8> Vault::make_key(const std::vector<u8> &salt,
                                std::uint32_t iterations) const {
  return derive_vault_key(password_, salt, iterations, kVaultKeyLen);
}

Vault::Vault(const std::filesystem::path &path, const std::string &password)
    : path_(path), password_(password) {
  const std::vector<std::uint8_t> raw = read_file_bytes(path_);
  if (raw.size() < kVaultHeaderLen) {
    throw std::runtime_error("Vault: file too short to be a valid vault");
  }
  if (!std::equal(kVaultMagic, kVaultMagic + 8, raw.begin())) {
    throw std::runtime_error("Vault: bad magic (not a vHSM vault)");
  }
  version_ = get_le32(raw.data() + 8);
  if (version_ != kVaultFormatVersion) {
    throw std::runtime_error("Vault: unsupported format version: " +
                             std::to_string(version_));
  }

  std::vector<u8> salt(kVaultSaltLen);
  std::memcpy(salt.data(), raw.data() + 12, salt.size());
  const std::uint32_t iterations = get_le32(raw.data() + 28);
  if (iterations == 0) {
    throw std::runtime_error("Vault: invalid PBKDF2 iteration count");
  }

  std::vector<u8> nonce(kVaultNonceLen);
  std::memcpy(nonce.data(), raw.data() + 32, nonce.size());
  std::vector<u8> tag(kVaultTagLen);
  std::memcpy(tag.data(), raw.data() + 44, tag.size());
  const std::uint64_t ct_len = get_le64(raw.data() + 60);
  if (raw.size() != kVaultHeaderLen + ct_len) {
    throw std::runtime_error(
        "Vault: ciphertext length does not match file size");
  }
  std::vector<u8> ciphertext(
      raw.begin() + static_cast<std::ptrdiff_t>(kVaultHeaderLen), raw.end());

  // Decrypt to authenticate; the GCM tag check throws on bad password or
  // corruption (fail-closed — never return wrong plaintext).
  const std::vector<u8> key = make_key(salt, iterations);
  crypto::AESGCMResult res{ciphertext, nonce, tag};
  try {
    (void)crypto::AESGCM::decrypt(key, res);
  } catch (const std::exception &) {
    OPENSSL_cleanse(const_cast<u8 *>(key.data()), key.size());
    throw std::runtime_error(
        "Vault: authentication failed (wrong password or corrupt file)");
  }
  OPENSSL_cleanse(const_cast<u8 *>(key.data()), key.size());
  valid_ = true;
}

// Static factory: create a brand new vault file.
Vault Vault::create(const std::filesystem::path &path,
                    const std::string &password,
                    const std::vector<u8> &initial_payload) {
  VHSM_CHECK_MSG(!password.empty(),
                 "Vault::create: password must not be empty");
  if (std::filesystem::exists(path)) {
    throw std::runtime_error("Vault::create: file already exists: " +
                             path.string());
  }
  // Build a not-yet-valid Vault (private ctor) so save() can produce the file
  // without first reading/authenticating a file that does not exist yet.
  Vault v(path, password, true);
  v.save(initial_payload);
  return v;
}

// Internal ctor used by create(): never reads the file.
Vault::Vault(const std::filesystem::path &path, const std::string &password,
             bool /*unused*/)
    : path_(path), password_(password), version_(kVaultFormatVersion),
      valid_(false) {}

void Vault::save(const std::vector<u8> &payload) {
  VHSM_CHECK_MSG(!password_.empty(), "Vault::save: no password available");

  // Fresh random salt on every write: each save re-derives a new key from the
  // same password. This prevents an attacker who captures successive file
  // snapshots from ever reusing the same key for different snapshots, and
  // makes the vault resilient to a leaked single key (only one snapshot is
  // affected, not the whole history).
  std::vector<u8> salt(kVaultSaltLen);
  VHSM_CHECK_MSG(RAND_bytes(salt.data(), static_cast<int>(salt.size())) == 1,
                 "Vault::save: RAND_bytes failed for salt");

  const std::vector<u8> key = make_key(salt, kVaultPbkdf2Iterations);
  const crypto::AESGCMResult enc = crypto::AESGCM::encrypt(key, payload);

  // Atomic write: write to a temp file in the SAME directory (so rename is
  // atomic on POSIX), fsync the file, then rename over the target, then fsync
  // the directory. Readers never observe a partially-written vault.
  static std::atomic<unsigned> temp_counter{0};
  const unsigned seq = temp_counter.fetch_add(1);
#ifdef _WIN32
  const int pid = ::_getpid();
#else
  const int pid = ::getpid();
#endif
  const std::filesystem::path tmp_path =
      path_.parent_path() / (path_.filename().string() + ".tmp" +
                             std::to_string(pid) + "-" + std::to_string(seq));

  // Build the vault image once — reused by both platform branches.
  std::vector<std::uint8_t> out;
  out.reserve(kVaultHeaderLen + enc.ciphertext.size());
  out.insert(out.end(), kVaultMagic, kVaultMagic + 8);
  put_le32(out, kVaultFormatVersion);
  out.insert(out.end(), salt.begin(), salt.end());
  put_le32(out, kVaultPbkdf2Iterations);
  out.insert(out.end(), enc.nonce.begin(), enc.nonce.end());
  out.insert(out.end(), enc.tag.begin(), enc.tag.end());
  put_le64(out, enc.ciphertext.size());
  out.insert(out.end(), enc.ciphertext.begin(), enc.ciphertext.end());

#ifdef _WIN32
  // Windows branch: use low-level _open/_write/_commit and MoveFileExW for
  // atomic replace. _commit flushes to disk (fsync equivalent).
  {
    const int fd = ::_open(tmp_path.string().c_str(),
                           _O_WRONLY | _O_CREAT | _O_TRUNC | _O_BINARY,
                           _S_IREAD | _S_IWRITE);
    if (fd < 0) {
      throw std::runtime_error("Vault::save: cannot create temp file: " +
                               tmp_path.string());
    }
    const std::size_t total = out.size();
    std::size_t written = 0;
    while (written < total) {
      int n = ::_write(fd, out.data() + written,
                       static_cast<unsigned>(total - written));
      if (n < 0) {
        const int err = errno;
        ::_close(fd);
        ::_unlink(tmp_path.string().c_str());
        throw std::runtime_error("Vault::save: write failed: " +
                                 std::string(std::strerror(err)));
      }
      written += static_cast<std::size_t>(n);
    }
    if (::_commit(fd) != 0) {
      const int err = errno;
      ::_close(fd);
      ::_unlink(tmp_path.string().c_str());
      throw std::runtime_error("Vault::save: commit failed: " +
                               std::string(std::strerror(err)));
    }
    if (::_close(fd) != 0) {
      const int err = errno;
      ::_unlink(tmp_path.string().c_str());
      throw std::runtime_error("Vault::save: close failed: " +
                               std::string(std::strerror(err)));
    }
  }
  // Atomic replace on Windows: MoveFileExW with REPLACE_EXISTING is atomic
  // when source and target are on the same volume (we kept tmp in same dir).
  if (!::MoveFileExW(tmp_path.wstring().c_str(), path_.wstring().c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    const DWORD err = ::GetLastError();
    ::_unlink(tmp_path.string().c_str());
    throw std::runtime_error("Vault::save: MoveFileExW failed: " +
                             std::to_string(err));
  }
  // Flush directory via CreateFileW + FlushFileBuffers
  {
    std::filesystem::path dir_path = path_.parent_path();
    if (dir_path.empty())
      dir_path = ".";
    HANDLE hDir = ::CreateFileW(
        dir_path.wstring().c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (hDir != INVALID_HANDLE_VALUE) {
      ::FlushFileBuffers(hDir);
      ::CloseHandle(hDir);
    }
  }
#else
  {
    const int fd = ::open(tmp_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
      throw std::runtime_error("Vault::save: cannot create temp file: " +
                               tmp_path.string());
    }

    const std::size_t total = out.size();
    std::size_t written = 0;
    while (written < total) {
      const ssize_t n = ::write(fd, out.data() + written, total - written);
      if (n < 0) {
        const int err = errno;
        ::close(fd);
        ::unlink(tmp_path.c_str());
        throw std::runtime_error("Vault::save: write failed: " +
                                 std::string(std::strerror(err)));
      }
      written += static_cast<std::size_t>(n);
    }
    if (::fsync(fd) != 0) {
      const int err = errno;
      ::close(fd);
      ::unlink(tmp_path.c_str());
      throw std::runtime_error("Vault::save: fsync failed: " +
                               std::string(std::strerror(err)));
    }
    if (::close(fd) != 0) {
      const int err = errno;
      ::unlink(tmp_path.c_str());
      throw std::runtime_error("Vault::save: close failed: " +
                               std::string(std::strerror(err)));
    }
  }

  if (::rename(tmp_path.c_str(), path_.c_str()) != 0) {
    const int err = errno;
    ::unlink(tmp_path.c_str());
    throw std::runtime_error("Vault::save: rename failed: " +
                             std::string(std::strerror(err)));
  }

  // fsync the directory so the rename is durable across a power loss.
  const std::string dir =
      path_.parent_path().empty() ? "." : path_.parent_path().string();
  const int dfd = ::open(dir.c_str(), O_RDONLY);
  if (dfd >= 0) {
    ::fsync(dfd);
    ::close(dfd);
  }
#endif

  // A successful write means the vault on disk is authentic and readable.
  valid_ = true;
}

std::vector<u8> Vault::load() const {
  if (!valid_) {
    throw std::runtime_error("Vault::load: vault is not valid");
  }
  const std::vector<std::uint8_t> raw = read_file_bytes(path_);
  if (raw.size() < kVaultHeaderLen ||
      !std::equal(kVaultMagic, kVaultMagic + 8, raw.begin())) {
    throw std::runtime_error("Vault::load: file is not a valid vault");
  }
  const std::uint32_t v = get_le32(raw.data() + 8);
  if (v != kVaultFormatVersion) {
    throw std::runtime_error("Vault::load: unsupported format version");
  }
  std::vector<u8> salt(kVaultSaltLen);
  std::memcpy(salt.data(), raw.data() + 12, salt.size());
  const std::uint32_t iterations = get_le32(raw.data() + 28);
  std::vector<u8> nonce(kVaultNonceLen);
  std::memcpy(nonce.data(), raw.data() + 32, nonce.size());
  std::vector<u8> tag(kVaultTagLen);
  std::memcpy(tag.data(), raw.data() + 44, tag.size());
  const std::uint64_t ct_len = get_le64(raw.data() + 60);
  if (raw.size() != kVaultHeaderLen + ct_len) {
    throw std::runtime_error("Vault::load: ciphertext length mismatch");
  }
  std::vector<u8> ciphertext(
      raw.begin() + static_cast<std::ptrdiff_t>(kVaultHeaderLen), raw.end());

  const std::vector<u8> key = make_key(salt, iterations);
  crypto::AESGCMResult res{ciphertext, nonce, tag};
  return crypto::AESGCM::decrypt(key, res);
}

} // namespace vhsm::persistence