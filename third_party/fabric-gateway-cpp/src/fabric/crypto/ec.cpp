#include "../../../include/fabric/crypto/ec.h"
#include "../../../include/fabric/crypto/x509.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <sstream>
#include <stdexcept>
#include <iomanip>

namespace fabric {
namespace crypto {

class ECKeyPair::Impl {
public:
    Impl() : ec_key_(nullptr) {
        ec_key_ = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); // P-256
        if (!ec_key_) {
            throw std::runtime_error("Failed to create EC key");
        }

        if (EC_KEY_generate_key(ec_key_) != 1) {
            EC_KEY_free(ec_key_);
            throw std::runtime_error("Failed to generate EC key");
        }
    }

    explicit Impl(const std::string& pem) : ec_key_(nullptr) {
        BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
        if (!bio) {
            throw std::runtime_error("Failed to create BIO from PEM");
        }

        ec_key_ = PEM_read_bio_ECPrivateKey(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (!ec_key_) {
            throw std::runtime_error("Failed to parse EC private key from PEM");
        }
    }

    ~Impl() {
        if (ec_key_) {
            EC_KEY_free(ec_key_);
        }
    }

    std::string getPrivateKeyPEM() const {
        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) {
            throw std::runtime_error("Failed to create BIO");
        }

        if (PEM_write_bio_ECPrivateKey(bio, ec_key_, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
            BIO_free(bio);
            throw std::runtime_error("Failed to write private key to PEM");
        }

        char* data;
        long len = BIO_get_mem_data(bio, &data);
        std::string result(data, len);
        BIO_free(bio);
        return result;
    }

    std::string getPublicKeyPEM() const {
        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) {
            throw std::runtime_error("Failed to create BIO");
        }

        if (PEM_write_bio_EC_PUBKEY(bio, ec_key_) != 1) {
            BIO_free(bio);
            throw std::runtime_error("Failed to write public key to PEM");
        }

        char* data;
        long len = BIO_get_mem_data(bio, &data);
        std::string result(data, len);
        BIO_free(bio);
        return result;
    }

    std::string sign(const std::string& data) const {
        unsigned int sig_len = 0;
        unsigned char* sig = nullptr;

        // Create signature
        sig = static_cast<unsigned char*>(OPENSSL_malloc(ECDSA_size(ec_key_)));
        if (!sig) {
            throw std::runtime_error("Failed to allocate memory for signature");
        }

        if (ECDSA_sign(0,
                      reinterpret_cast<const unsigned char*>(data.data()),
                      static_cast<int>(data.size()),
                      sig, &sig_len, ec_key_) != 1) {
            OPENSSL_free(sig);
            throw std::runtime_error("Failed to sign data");
        }

        // Convert to hex string
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (unsigned int i = 0; i < sig_len; ++i) {
            ss << std::setw(2) << static_cast<int>(sig[i]);
        }

        OPENSSL_free(sig);
        return ss.str();
    }

    bool verify(const std::string& data, const std::string& signature) const {
        // Convert hex signature back to bytes
        std::vector<unsigned char> sigBytes;
        if (signature.size() % 2 != 0) {
            return false;
        }

        for (size_t i = 0; i < signature.size(); i += 2) {
            std::string byteString = signature.substr(i, 2);
            unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
            sigBytes.push_back(byte);
        }

        // Verify signature
        return ECDSA_verify(0,
                           reinterpret_cast<const unsigned char*>(data.data()),
                           static_cast<int>(data.size()),
                           sigBytes.data(),
                           static_cast<int>(sigBytes.size()),
                           ec_key_) == 1;
    }

private:
    EC_KEY* ec_key_;
};

// Static method implementation
std::pair<std::string, std::string> ECKeyPair::generate() {
    Impl impl;
    return {impl.getPrivateKeyPEM(), impl.getPublicKeyPEM()};
}

// Constructor
ECKeyPair::ECKeyPair(const std::string& pem) : pimpl_(std::make_unique<Impl>(pem)) {}

// Getters
std::string ECKeyPair::getPrivateKeyPEM() const {
    return pimpl_->getPrivateKeyPEM();
}

std::string ECKeyPair::getPublicKeyPEM() const {
    return pimpl_->getPublicKeyPEM();
}

// Signing
std::string ECKeyPair::sign(const std::string& data) const {
    return pimpl_->sign(data);
}

// Verification
bool ECKeyPair::verify(const std::string& data, const std::string& signature) const {
    return pimpl_->verify(data, signature);
}

} // namespace crypto
} // namespace fabric