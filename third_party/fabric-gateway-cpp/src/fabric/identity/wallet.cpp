#include "fabric/identity/wallet.h"
#include <unordered_map>
#include <mutex>

namespace fabric {
namespace identity {

class InMemoryWallet::Impl {
public:
    std::unordered_map<std::string, Identity> identities_;
    std::mutex mutex_;
};

InMemoryWallet::InMemoryWallet() : pimpl_(std::make_unique<Impl>()) {}

InMemoryWallet::~InMemoryWallet() = default;

bool InMemoryWallet::put(const std::string& label, const Identity& identity) {
    std::lock_guard<std::mutex> lock(pimpl_->mutex_);
    pimpl_->identities_[label] = identity;
    return true;
}

std::unique_ptr<Identity> InMemoryWallet::get(const std::string& label) {
    std::lock_guard<std::mutex> lock(pimpl_->mutex_);
    auto it = pimpl_->identities_.find(label);
    if (it != pimpl_->identities_.end()) {
        return std::make_unique<Identity>(it->second);
    }
    return nullptr;
}

bool InMemoryWallet::deleteIdentity(const std::string& label) {
    std::lock_guard<std::mutex> lock(pimpl_->mutex_);
    auto it = pimpl_->identities_.find(label);
    if (it != pimpl_->identities_.end()) {
        pimpl_->identities_.erase(it);
        return true;
    }
    return false;
}

bool InMemoryWallet::exists(const std::string& label) {
    std::lock_guard<std::mutex> lock(pimpl_->mutex_);
    return pimpl_->identities_.find(label) != pimpl_->identities_.end();
}

std::vector<std::string> InMemoryWallet::list() {
    std::lock_guard<std::mutex> lock(pimpl_->mutex_);
    std::vector<std::string> result;
    result.reserve(pimpl_->identities_.size());
    for (const auto& pair : pimpl_->identities_) {
        result.push_back(pair.first);
    }
    return result;
}

class FileSystemWallet::Impl {
public:
    std::string directoryPath_;
};

FileSystemWallet::FileSystemWallet(const std::string& directoryPath)
    : pimpl_(std::make_unique<Impl>()), directoryPath_(directoryPath) {
    // Ensure directory exists
    #ifdef _WIN32
    _mkdir(directoryPath_.c_str());
    #else
    mkdir(directoryPath_.c_str(), 0755);
    #endif
}

FileSystemWallet::~FileSystemWallet() = default;

bool FileSystemWallet::put(const std::string& label, const Identity& identity) {
    // Create safe filename from label
    std::string filename = directoryPath_ + "/" + label + ".id";

    // Save certificate and private key to files
    std::string certFile = filename + ".cert";
    std::string keyFile = filename + ".key";

    FILE* certFp = fopen(certFile.c_str(), "w");
    if (!certFp) {
        return false;
    }
    fprintf(certFp, "%s", identity.getCertificate().c_str());
    fclose(certFp);

    FILE* keyFp = fopen(keyFile.c_str(), "w");
    if (!keyFp) {
        // Clean up cert file if key file fails
        remove(certFile.c_str());
        return false;
    }
    fprintf(keyFp, "%s", identity.getPrivateKey().c_str());
    fclose(keyFp);

    // Also save MSP ID
    std::string mspFile = filename + ".msp";
    FILE* mspFp = fopen(mspFile.c_str(), "w");
    if (!mspFp) {
        // Clean up files if MSP file fails
        remove(certFile.c_str());
        remove(keyFile.c_str());
        return false;
    }
    fprintf(mspFp, "%s", identity.getMSPID().c_str());
    fclose(mspFp);

    return true;
}

std::unique_ptr<Identity> FileSystemWallet::get(const std::string& label) {
    std::string filename = directoryPath_ + "/" + label + ".id";
    std::string certFile = filename + ".cert";
    std::string keyFile = filename + ".key";
    std::string mspFile = filename + ".msp";

    // Check if all files exist
    FILE* certFp = fopen(certFile.c_str(), "r");
    if (!certFp) {
        return nullptr;
    }
    fseek(certFp, 0, SEEK_END);
    long certLen = ftell(certFp);
    fseek(certFp, 0, SEEK_SET);
    std::string cert(certLen, '\0');
    fread(&cert[0], 1, certLen, certFp);
    fclose(certFp);

    FILE* keyFp = fopen(keyFile.c_str(), "r");
    if (!keyFp) {
        return nullptr;
    }
    fseek(keyFp, 0, SEEK_END);
    long keyLen = ftell(keyFp);
    fseek(keyFp, 0, SEEK_SET);
    std::string key(keyLen, '\0');
    fread(&key[0], 1, keyLen, keyFp);
    fclose(keyFp);

    FILE* mspFp = fopen(mspFile.c_str(), "r");
    if (!mspFp) {
        return nullptr;
    }
    fseek(mspFp, 0, SEEK_END);
    long mspLen = ftell(mspFp);
    fseek(mspFp, 0, SEEK_SET);
    std::string msp(mspLen, '\0');
    fread(&msp[0], 1, mspLen, mspFp);
    fclose(mspFp);

    return std::make_unique<Identity>(msp, cert, key);
}

bool FileSystemWallet::deleteIdentity(const std::string& label) {
    std::string filename = directoryPath_ + "/" + label + ".id";
    std::string certFile = filename + ".cert";
    std::string keyFile = filename + ".key";
    std::string mspFile = filename + ".msp";

    remove(certFile.c_str());
    remove(keyFile.c_str());
    remove(mspFile.c_str());

    return true;
}

bool FileSystemWallet::exists(const std::string& label) {
    std::string filename = directoryPath_ + "/" + label + ".id";
    std::string certFile = filename + ".cert";
    std::string keyFile = filename + ".key";
    std::string mspFile = filename + ".msp";

    FILE* certFp = fopen(certFile.c_str(), "r");
    FILE* keyFp = fopen(keyFile.c_str(), "r");
    FILE* mspFp = fopen(mspFile.c_str(), "r");

    bool exists = certFp && keyFp && mspFp;

    if (certFp) fclose(certFp);
    if (keyFp) fclose(keyFp);
    if (mspFp) fclose(mspFp);

    return exists;
}

std::vector<std::string> FileSystemWallet::list() {
    std::vector<std::string> result;

    // This is a simplified implementation - in practice would scan directory
    // For now, we'll return an empty list as implementing proper directory scanning
    // is platform-specific and beyond the scope of this implementation
    return result;
}

} // namespace identity
} // namespace fabric