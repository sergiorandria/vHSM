#include "../../../include/fabric/crypto/x509.h"

#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <chrono>
#include <stdexcept>
#include <vector>

namespace fabric {
namespace crypto {

class X509Certificate::Impl {
public:
    explicit Impl(const std::string& certPEM) : cert_(nullptr) {
        BIO* bio = BIO_new_mem_buf(certPEM.data(), static_cast<int>(certPEM.size()));
        if (!bio) {
            throw std::runtime_error("Failed to create BIO from certificate PEM");
        }

        cert_ = PEM_read_bio_X509_AUX(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (!cert_) {
            throw std::runtime_error("Failed to parse certificate from PEM");
        }
    }

    ~Impl() {
        if (cert_) {
            X509_free(cert_);
        }
    }

    std::string getPEM() const {
        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) {
            throw std::runtime_error("Failed to create BIO");
        }

        if (PEM_write_bio_X509_AUX(bio, cert_) != 1) {
            BIO_free(bio);
            throw std::runtime_error("Failed to write certificate to PEM");
        }

        char* data;
        long len = BIO_get_mem_data(bio, &data);
        std::string result(data, len);
        BIO_free(bio);
        return result;
    }

    std::string getSubjectCommonName() const {
        X509_NAME* subjectName = X509_get_subject_name(cert_);
        if (!subjectName) {
            return "";
        }

        int loc = X509_NAME_get_index_by_NID(subjectName, NID_commonName, -1);
        if (loc < 0) {
            return "";
        }

        X509_NAME_ENTRY* entry = X509_NAME_get_entry(subjectName, loc);
        if (!entry) {
            return "";
        }

        ASN1_STRING* value = X509_NAME_ENTRY_get_data(entry);
        if (!value) {
            return "";
        }

        unsigned char* buf = nullptr;
        int len = ASN1_STRING_to_UTF8(&buf, value);
        if (len < 0) {
            return "";
        }

        std::string result(reinterpret_cast<char*>(buf), len);
        OPENSSL_free(buf);
        return result;
    }

    std::string getIssuer() const {
        X509_NAME* issuerName = X509_get_issuer_name(cert_);
        if (!issuerName) {
            return "";
        }

        char* buf = X509_NAME_oneline(issuerName, nullptr, 0);
        if (!buf) {
            return "";
        }

        std::string result(buf);
        OPENSSL_free(buf);
        return result;
    }

    std::string getSerialNumber() const {
        ASN1_INTEGER* serial = X509_get_serialNumber(cert_);
        if (!serial) {
            return "";
        }

        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) {
            return "";
        }

        if (i2a_ASN1_INTEGER(bio, serial) <= 0) {
            BIO_free(bio);
            return "";
        }

        char* data;
        long len = BIO_get_mem_data(bio, &data);
        std::string result(data, len);
        BIO_free(bio);
        return result;
    }

    std::chrono::system_clock::time_point getNotBefore() const {
        ASN1_TIME* time = X509_get_notBefore(cert_);
        if (!time) {
            return std::chrono::system_clock::time_point();
        }

        return asn1TimeToSystemPoint(time);
    }

    std::chrono::system_clock::time_point getNotAfter() const {
        ASN1_TIME* time = X509_get_notAfter(cert_);
        if (!time) {
            return std::chrono::system_clock::time_point();
        }

        return asn1TimeToSystemPoint(time);
    }

    bool isValid() const {
        auto now = std::chrono::system_clock::now();
        auto notBefore = getNotBefore();
        auto notAfter = getNotAfter();

        if (notBefore == std::chrono::system_clock::time_point() ||
            notAfter == std::chrono::system_clock::time_point()) {
            return false;
        }

        return now >= notBefore && now <= notAfter;
    }

    std::string getPublicKeyPEM() const {
        EVP_PKEY* pkey = X509_get_pubkey(cert_);
        if (!pkey) {
            throw std::runtime_error("Failed to get public key from certificate");
        }

        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) {
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to create BIO for public key");
        }

        if (PEM_write_bio_PUBKEY(bio, pkey) != 1) {
            BIO_free(bio);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to write public key to PEM");
        }

        char* data;
        long len = BIO_get_mem_data(bio, &data);
        std::string result(data, len);

        BIO_free(bio);
        EVP_PKEY_free(pkey);
        return result;
    }

    std::vector<std::string> getSubjectAlternativeNames() const {
        std::vector<std::string> sans;
        int loc = -1;

        while ((loc = X509_get_ext_by_NID(cert_, NID_subject_alt_name, loc)) >= 0) {
            X509_EXTENSION* ext = X509_get_ext(cert_, loc);
            if (!ext) continue;

            ASN1_OBJECT* obj = X509_EXTENSION_get_object(ext);
            if (!obj) continue;

            const char* extName = OBJ_nid2ln(OBJ_obj2nid(obj));
            if (!extName || std::string(extName) != "subjectAltName") continue;

            ASN1_OCTET_STRING* extValue = X509_EXTENSION_get_data(ext);
            if (!extValue) continue;

            STACK_OF(GENERAL_NAME)* sanStack = nullptr;
            const unsigned char* pp = extValue->data;
            sanStack = d2i_GENERAL_NAMES(nullptr, &pp, extValue->length);
            if (!sanStack) continue;

            int sanCount = sk_GENERAL_NAME_num(sanStack);
            for (int i = 0; i < sanCount; ++i) {
                GENERAL_NAME* san = sk_GENERAL_NAME_value(sanStack, i);
                if (san->type == GEN_DNS) {
                    unsigned char* dns = nullptr;
                    int len = ASN1_STRING_to_UTF8(&dns, san->d.dNSName);
                    if (len > 0 && dns) {
                        sans.push_back(std::string(
                            reinterpret_cast<char*>(dns), len));
                        OPENSSL_free(dns);
                    }
                }
            }

            sk_GENERAL_NAME_free(sanStack);
        }

        return sans;
    }

private:
    std::chrono::system_clock::time_point asn1TimeToSystemPoint(const ASN1_TIME* time) const {
        if (!time) {
            return std::chrono::system_clock::time_point();
        }

        // Convert ASN1_TIME to tm struct
        struct tm tm_time = {};
        if (!ASN1_TIME_to_tm(time, &tm_time)) {
            return std::chrono::system_clock::time_point();
        }

        // Convert tm to time_t (seconds since epoch)
        std::time_t time_t_time = std::mktime(&tm_time);
        if (time_t_time == -1) {
            return std::chrono::system_clock::time_point();
        }

        // Convert to system_clock::time_point
        return std::chrono::system_clock::from_time_t(time_t_time);
    }

    X509* cert_;
};

// Constructor
X509Certificate::X509Certificate(const std::string& certPEM) : pimpl_(std::make_unique<Impl>(certPEM)) {}

// Getters
std::string X509Certificate::getPEM() const {
    return pimpl_->getPEM();
}

std::string X509Certificate::getSubjectCommonName() const {
    return pimpl_->getSubjectCommonName();
}

std::string X509Certificate::getIssuer() const {
    return pimpl_->getIssuer();
}

std::string X509Certificate::getSerialNumber() const {
    return pimpl_->getSerialNumber();
}

std::chrono::system_clock::time_point X509Certificate::getNotBefore() const {
    return pimpl_->getNotBefore();
}

std::chrono::system_clock::time_point X509Certificate::getNotAfter() const {
    return pimpl_->getNotAfter();
}

bool X509Certificate::isValid() const {
    return pimpl_->isValid();
}

std::string X509Certificate::getPublicKeyPEM() const {
    return pimpl_->getPublicKeyPEM();
}

std::vector<std::string> X509Certificate::getSubjectAlternativeNames() const {
    return pimpl_->getSubjectAlternativeNames();
}

} // namespace crypto
} // namespace fabric