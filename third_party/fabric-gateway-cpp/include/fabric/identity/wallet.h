#ifndef FABRIC_IDENTITY_WALLET_H
#define FABRIC_IDENTITY_WALLET_H

#include <string>
#include <memory>
#include <vector>
#include "identity.h"

namespace fabric {
namespace identity {

/**
 * Abstract wallet interface for storing and retrieving identities
 */
class Wallet {
public:
    virtual ~Wallet() = default;

    /**
     * Put an identity into the wallet
     * @param label Label to identify the identity
     * @param identity Identity to store
     * @return True if successful
     */
    virtual bool put(const std::string& label, const Identity& identity) = 0;

    /**
     * Get an identity from the wallet
     * @param label Label identifying the identity
     * @return Identity if found, nullopt otherwise
     */
    virtual std::unique_ptr<Identity> get(const std::string& label) = 0;

    /**
     * Delete an identity from the wallet
     * @param label Label identifying the identity to delete
     * @return True if successful
     */
    virtual bool deleteIdentity(const std::string& label) = 0;

    /**
     * Check if an identity exists in the wallet
     * @param label Label to check
     * @return True if identity exists
     */
    virtual bool exists(const std::string& label) = 0;

    /**
     * List all labels in the wallet
     * @return Vector of identity labels
     */
    virtual std::vector<std::string> list() = 0;
};

/**
 * In-memory wallet implementation
 */
class InMemoryWallet : public Wallet {
public:
    InMemoryWallet();
    ~InMemoryWallet() override;

    bool put(const std::string& label, const Identity& identity) override;
    std::unique_ptr<Identity> get(const std::string& label) override;
    bool deleteIdentity(const std::string& label) override;
    bool exists(const std::string& label) override;
    std::vector<std::string> list() override;

private:
    class Impl;
    std::unique_ptr<Impl> pimpl_;
};

/**
 * File system wallet implementation
 * Stores identities as files in a directory structure
 */
class FileSystemWallet : public Wallet {
public:
    /**
     * Create a file system wallet
     * @param directoryPath Path to directory where identities will be stored
     */
    explicit FileSystemWallet(const std::string& directoryPath);
    ~FileSystemWallet() override;

    bool put(const std::string& label, const Identity& identity) override;
    std::unique_ptr<Identity> get(const std::string& label) override;
    bool deleteIdentity(const std::string& label) override;
    bool exists(const std::string& label) override;
    std::vector<std::string> list() override;

private:
    class Impl;
    std::unique_ptr<Impl> pimpl_;
    std::string directoryPath_;
};

} // namespace identity
} // namespace fabric

#endif // FABRIC_IDENTITY_WALLET_H