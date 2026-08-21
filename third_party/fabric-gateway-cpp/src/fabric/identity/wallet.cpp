#include "../../../include/fabric/identity/wallet.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <functional>
#include <mutex>
#include <unordered_map>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace fabric {
namespace identity {

namespace {

constexpr unsigned char kMagic[4] = {'F', 'H', 'W', 'M'};
constexpr int kVersion = 1;
constexpr int kNonceLen = 12;
constexpr int kTagLen = 16;
constexpr size_t kKeyLen = 32;
constexpr mode_t kDirMode = 0700;
constexpr mode_t kFileMode = 0600;

bool isValidLabel(const std::string &label) {
  if (label.empty() || label.size() > 128) {
    return false;
  }
  if (label == "." || label == "..") {
    return false;
  }
  for (char c : label) {
    if (c == '/' || c == '\\' || c == '\0' || static_cast<unsigned char>(c) < 0x20) {
      return false;
    }
    if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_' || c == '-')) {
      return false;
    }
  }
  return true;
}

std::vector<unsigned char> hexDecode(const std::string &hex) {
  auto nibble = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  if (hex.size() % 2 != 0) {
    return {};
  }
  std::vector<unsigned char> out;
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    int hi = nibble(hex[i]);
    int lo = nibble(hex[i + 1]);
    if (hi < 0 || lo < 0) {
      return {};
    }
    out.push_back(static_cast<unsigned char>((hi << 4) | lo));
  }
  return out;
}

std::string serializeIdentity(const Identity &id) {
  std::string s;
  s += id.getMSPID();
  s.push_back('\0');
  s += id.getCertificate();
  s.push_back('\0');
  s += id.getPrivateKey();
  return s;
}

std::unique_ptr<Identity> deserializeIdentity(const std::string &pt) {
  const size_t p1 = pt.find('\0');
  if (p1 == std::string::npos) {
    return nullptr;
  }
  const size_t p2 = pt.find('\0', p1 + 1);
  if (p2 == std::string::npos) {
    return nullptr;
  }
  std::string msp = pt.substr(0, p1);
  std::string cert = pt.substr(p1 + 1, p2 - (p1 + 1));
  std::string key = pt.substr(p2 + 1);
  return std::make_unique<Identity>(msp, cert, key);
}

bool evpEncrypt(const std::vector<unsigned char> &key, const std::string &plaintext,
                std::string &out) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    return false;
  }
  unsigned char nonce[kNonceLen];
  if (RAND_bytes(nonce, kNonceLen) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kNonceLen, nullptr) != 1 ||
      EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  std::string ct;
  ct.resize(plaintext.size());
  int len = 0;
  if (!plaintext.empty() &&
      EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char *>(&ct[0]), &len,
                        reinterpret_cast<const unsigned char *>(plaintext.data()),
                        static_cast<int>(plaintext.size())) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  int finalLen = 0;
  if (EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char *>(&ct[0]) + len, &finalLen) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  unsigned char tag[kTagLen];
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kTagLen, tag) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  EVP_CIPHER_CTX_free(ctx);

  out.clear();
  out.append(reinterpret_cast<const char *>(kMagic), 4);
  out.push_back(static_cast<char>(kVersion));
  out.append(reinterpret_cast<const char *>(nonce), kNonceLen);
  out.append(reinterpret_cast<const char *>(tag), kTagLen);
  out += ct;
  return true;
}

bool evpDecrypt(const std::vector<unsigned char> &key, const std::string &in, std::string &out) {
  const size_t header = 4 + 1 + kNonceLen + kTagLen;
  if (in.size() < header) {
    return false;
  }
  if (std::memcmp(in.data(), kMagic, 4) != 0) {
    return false;
  }
  const unsigned char *nonce = reinterpret_cast<const unsigned char *>(in.data()) + 5;
  const unsigned char *tag = nonce + kNonceLen;
  const char *ct = in.data() + header;
  const size_t ctLen = in.size() - header;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    return false;
  }
  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kNonceLen, nullptr) != 1 ||
      EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  std::string pt;
  pt.resize(ctLen);
  int len = 0;
  if (ctLen > 0 &&
      EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char *>(&pt[0]), &len,
                        reinterpret_cast<const unsigned char *>(ct), static_cast<int>(ctLen)) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, kTagLen, const_cast<unsigned char *>(tag)) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  int finalLen = 0;
  if (EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char *>(&pt[0]) + len, &finalLen) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  EVP_CIPHER_CTX_free(ctx);
  out = pt;
  return true;
}

bool readFile(const std::string &path, std::string &out) {
  int fd = open(path.c_str(), O_RDONLY);
  if (fd < 0) {
    return false;
  }
  struct stat st {};
  if (fstat(fd, &st) != 0) {
    close(fd);
    return false;
  }
  out.resize(static_cast<size_t>(st.st_size));
  size_t off = 0;
  while (off < out.size()) {
    ssize_t r = read(fd, &out[off], out.size() - off);
    if (r < 0) {
      if (errno == EINTR) {
        continue;
      }
      close(fd);
      return false;
    }
    if (r == 0) {
      break;
    }
    off += static_cast<size_t>(r);
  }
  close(fd);
  out.resize(off);
  return true;
}

bool writeFileAtomic(const std::string &finalPath, const std::string &data) {
  std::string tmp = finalPath + ".tmp";
  unlink(tmp.c_str());
  int fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_TRUNC, kFileMode);
  if (fd < 0) {
    return false;
  }
  size_t off = 0;
  while (off < data.size()) {
    ssize_t w = write(fd, data.data() + off, data.size() - off);
    if (w < 0) {
      if (errno == EINTR) {
        continue;
      }
      close(fd);
      unlink(tmp.c_str());
      return false;
    }
    off += static_cast<size_t>(w);
  }
  if (fsync(fd) != 0) {
    close(fd);
    unlink(tmp.c_str());
    return false;
  }
  close(fd);
  if (chmod(tmp.c_str(), kFileMode) != 0) {
    unlink(tmp.c_str());
    return false;
  }
  if (rename(tmp.c_str(), finalPath.c_str()) != 0) {
    unlink(tmp.c_str());
    return false;
  }
  return true;
}

void secureDelete(const std::string &path) {
  int fd = open(path.c_str(), O_WRONLY, kFileMode);
  if (fd >= 0) {
    struct stat st {};
    if (fstat(fd, &st) == 0) {
      const std::vector<char> zeros(4096, 0);
      size_t total = static_cast<size_t>(st.st_size);
      size_t off = 0;
      while (off < total) {
        size_t chunk = std::min(zeros.size(), total - off);
        ssize_t w = write(fd, zeros.data(), chunk);
        if (w <= 0) {
          break;
        }
        off += static_cast<size_t>(w);
      }
      fsync(fd);
    }
    close(fd);
  }
  unlink(path.c_str());
}

int mkdirs(const std::string &path, mode_t mode) {
  std::string cur;
  for (size_t i = 0; i < path.size(); ++i) {
    cur.push_back(path[i]);
    if (path[i] == '/' || i + 1 == path.size()) {
      if (cur == "/") {
        continue;
      }
      if (mkdir(cur.c_str(), mode) != 0 && errno != EEXIST) {
        return -1;
      }
      chmod(cur.c_str(), mode);
    }
  }
  return 0;
}

class WalletLock {
public:
  explicit WalletLock(const std::string &lockPath) : fd_(-1) {
    fd_ = open(lockPath.c_str(), O_WRONLY | O_CREAT, kFileMode);
    if (fd_ >= 0) {
      flock(fd_, LOCK_EX);
    }
  }
  ~WalletLock() {
    if (fd_ >= 0) {
      flock(fd_, LOCK_UN);
      close(fd_);
    }
  }
  explicit operator bool() const { return fd_ >= 0; }

private:
  int fd_;
};

}  // namespace

class InMemoryWallet::Impl {
public:
  std::unordered_map<std::string, Identity> identities_;
  std::mutex mutex_;
};

InMemoryWallet::InMemoryWallet() : pimpl_(std::make_unique<Impl>()) {}

InMemoryWallet::~InMemoryWallet() = default;

bool InMemoryWallet::put(const std::string &label, const Identity &identity) {
  std::lock_guard<std::mutex> lock(pimpl_->mutex_);
  return pimpl_->identities_.emplace(label, identity).second;
}

std::unique_ptr<Identity> InMemoryWallet::get(const std::string &label) {
  std::lock_guard<std::mutex> lock(pimpl_->mutex_);
  auto it = pimpl_->identities_.find(label);
  if (it != pimpl_->identities_.end()) {
    return std::make_unique<Identity>(it->second);
  }
  return nullptr;
}

bool InMemoryWallet::deleteIdentity(const std::string &label) {
  std::lock_guard<std::mutex> lock(pimpl_->mutex_);
  return pimpl_->identities_.erase(label) > 0;
}

bool InMemoryWallet::exists(const std::string &label) {
  std::lock_guard<std::mutex> lock(pimpl_->mutex_);
  return pimpl_->identities_.find(label) != pimpl_->identities_.end();
}

std::vector<std::string> InMemoryWallet::list() {
  std::lock_guard<std::mutex> lock(pimpl_->mutex_);
  std::vector<std::string> result;
  result.reserve(pimpl_->identities_.size());
  for (const auto &pair : pimpl_->identities_) {
    result.push_back(pair.first);
  }
  return result;
}

class CustomHardenedWallet::Impl {
public:
  Impl(const std::string &baseDirectory, const std::string &masterKeyEnvVar)
      : dir_(baseDirectory), masterKeyEnv_(masterKeyEnvVar) {
    while (!dir_.empty() && dir_.back() == '/') {
      dir_.pop_back();
    }
    loadMasterKey();
    mkdirs(dir_, kDirMode);
    chmod(dir_.c_str(), kDirMode);
  }

  void loadMasterKey() {
    const char *env = std::getenv(masterKeyEnv_.c_str());
    if (!env) {
      keyValid_ = false;
      return;
    }
    std::string hex(env);
    hex.erase(std::remove_if(hex.begin(), hex.end(),
                             [](unsigned char c) { return std::isspace(c); }),
              hex.end());
    masterKey_ = hexDecode(hex);
    keyValid_ = (masterKey_.size() == kKeyLen);
  }

  std::string pathFor(const std::string &label) const { return dir_ + "/" + label + ".id"; }

  bool keyValid_ = false;
  std::vector<unsigned char> masterKey_;
  std::string dir_;
  std::string masterKeyEnv_;
  mutable std::mutex mutex_;
};

CustomHardenedWallet::CustomHardenedWallet(const std::string &baseDirectory,
                                           const std::string &masterKeyEnvVar)
    : pimpl_(std::make_unique<Impl>(baseDirectory, masterKeyEnvVar)) {}

CustomHardenedWallet::~CustomHardenedWallet() = default;

bool CustomHardenedWallet::hasMasterKey() const { return pimpl_->keyValid_; }

bool CustomHardenedWallet::put(const std::string &label, const Identity &identity) {
  if (!isValidLabel(label) || !pimpl_->keyValid_) {
    return false;
  }
  WalletLock lock(pimpl_->dir_ + "/.lock");
  if (!lock) {
    return false;
  }
  std::string plaintext = serializeIdentity(identity);
  std::string blob;
  if (!evpEncrypt(pimpl_->masterKey_, plaintext, blob)) {
    return false;
  }
  OPENSSL_cleanse(const_cast<char *>(plaintext.data()), plaintext.size());
  return writeFileAtomic(pimpl_->pathFor(label), blob);
}

std::unique_ptr<Identity> CustomHardenedWallet::get(const std::string &label) {
  if (!isValidLabel(label) || !pimpl_->keyValid_) {
    return nullptr;
  }
  WalletLock lock(pimpl_->dir_ + "/.lock");
  if (!lock) {
    return nullptr;
  }
  std::string blob;
  if (!readFile(pimpl_->pathFor(label), blob)) {
    return nullptr;
  }
  std::string plaintext;
  if (!evpDecrypt(pimpl_->masterKey_, blob, plaintext)) {
    return nullptr;
  }
  auto id = deserializeIdentity(plaintext);
  OPENSSL_cleanse(const_cast<char *>(plaintext.data()), plaintext.size());
  return id;
}

bool CustomHardenedWallet::deleteIdentity(const std::string &label) {
  if (!isValidLabel(label)) {
    return false;
  }
  WalletLock lock(pimpl_->dir_ + "/.lock");
  if (!lock) {
    return false;
  }
  secureDelete(pimpl_->pathFor(label));
  return true;
}

bool CustomHardenedWallet::exists(const std::string &label) {
  if (!isValidLabel(label)) {
    return false;
  }
  WalletLock lock(pimpl_->dir_ + "/.lock");
  if (!lock) {
    return false;
  }
  struct stat st {};
  return stat(pimpl_->pathFor(label).c_str(), &st) == 0;
}

std::vector<std::string> CustomHardenedWallet::list() {
  std::vector<std::string> result;
  WalletLock lock(pimpl_->dir_ + "/.lock");
  if (!lock) {
    return result;
  }
  DIR *d = opendir(pimpl_->dir_.c_str());
  if (!d) {
    return result;
  }
  const std::string suffix = ".id";
  struct dirent *ent = nullptr;
  while ((ent = readdir(d)) != nullptr) {
    std::string name = ent->d_name;
    if (name == "." || name == "..") {
      continue;
    }
    if (name.size() <= suffix.size() ||
        name.compare(name.size() - suffix.size(), suffix.size(), suffix) != 0) {
      continue;
    }
    result.push_back(name.substr(0, name.size() - suffix.size()));
  }
  closedir(d);
  return result;
}

}  // namespace identity
}  // namespace fabric
