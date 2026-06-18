#include "../../../include/fabric/crypto/csr.h"
#include "../../../include/fabric/crypto/ec.h"
#include "../../../include/fabric/crypto/x509.h"

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace fabric {
namespace crypto {

std::string CSR::generate(
    const std::string& privateKeyPEM,
    const std::string& commonName,
    const std::string& organization,
    const std::string& organizationalUnit,
    const std::string& locality,
    const std::string& state,
    const std::string& country,
    const std::vector<std::string>& sans)
{
    // Load private key
    BIO* keyBio = BIO_new_mem_buf(privateKeyPEM.data(), static_cast<int>(privateKeyPEM.size()));
    if (!keyBio) {
        throw std::runtime_error("Failed to create BIO for private key");
    }

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(keyBio, nullptr, nullptr, nullptr);
    BIO_free(keyBio);

    if (!pkey) {
        throw std::runtime_error("Failed to parse private key");
    }

    // Create CSR request
    X509_REQ* req = X509_REQ_new();
    if (!req) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to create CSR request");
    }

    // Set version
    if (X509_REQ_set_version(req, 0L) != 1) { // Version 0
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to set CSR version");
    }

    // Set subject
    X509_NAME* name = X509_NAME_new();
    if (!name) {
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to create X509_NAME");
    }

    if (!commonName.empty() &&
        X509_NAME_add_entry_by_txt(name, "CN",  MBSTRING_ASC,
                                 reinterpret_cast<const unsigned char*>(commonName.c_str()),
                                 -1, -1, 0) != 1) {
        X509_NAME_free(name);
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to add CN to subject");
    }

    if (!organization.empty() &&
        X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC,
                                 reinterpret_cast<const unsigned char*>(organization.c_str()),
                                 -1, -1, 0) != 1) {
        X509_NAME_free(name);
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to add O to subject");
    }

    if (!organizationalUnit.empty() &&
        X509_NAME_add_entry_by_txt(name, "OU",  MBSTRING_ASC,
                                 reinterpret_cast<const unsigned char*>(organizationalUnit.c_str()),
                                 -1, -1, 0) != 1) {
        X509_NAME_free(name);
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to add OU to subject");
    }

    if (!locality.empty() &&
        X509_NAME_add_entry_by_txt(name, "L",  MBSTRING_ASC,
                                 reinterpret_cast<const unsigned char*>(locality.c_str()),
                                 -1, -1, 0) != 1) {
        X509_NAME_free(name);
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to add L to subject");
    }

    if (!state.empty() &&
        X509_NAME_add_entry_by_txt(name, "ST",  MBSTRING_ASC,
                                 reinterpret_cast<const unsigned char*>(state.c_str()),
                                 -1, -1, 0) != 1) {
        X509_NAME_free(name);
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to add ST to subject");
    }

    if (!country.empty() &&
        X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC,
                                 reinterpret_cast<const unsigned char*>(country.c_str()),
                                 -1, -1, 0) != 1) {
        X509_NAME_free(name);
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to add C to subject");
    }

    if (X509_REQ_set_subject_name(req, name) != 1) {
        X509_NAME_free(name);
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to set subject name");
    }
    X509_NAME_free(name);

    // Set public key
    if (X509_REQ_set_pubkey(req, pkey) != 1) {
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to set public key");
    }

    // Add SANs if provided
    if (!sans.empty()) {
        STACK_OF(X509_EXTENSION)* ext = nullptr;
        X509V3_CTX ctx;
        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, nullptr, nullptr, req, nullptr, 0);

        std::string sanList;
        for (size_t i = 0; i < sans.size(); ++i) {
            if (i > 0) sanList += ",";
            sanList += "DNS:" + sans[i];
        }

        X509_EXTENSION* extItem = X509V3_EXT_conf_nid(nullptr, &ctx, OBJ_txt2nid("subjectAltName"), sanList.c_str());
        if (extItem) {
            ext = sk_X509_EXTENSION_new_null();
            if (ext && sk_X509_EXTENSION_push(ext, extItem) != 1) {
                sk_X509_EXTENSION_free(ext);
                ext = nullptr;
            }
            X509_EXTENSION_free(extItem);
        }

        if (ext && X509_REQ_add_extensions(req, ext) != 1) {
            sk_X509_EXTENSION_free(ext);
            X509_REQ_free(req);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to add SAN extension");
        }

        if (ext) sk_X509_EXTENSION_free(ext);
    }

    // Sign the CSR
    if (X509_REQ_sign(req, pkey, EVP_sha256()) != 1) {
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to sign CSR");
    }

    // Convert to PEM
    BIO* outBio = BIO_new(BIO_s_mem());
    if (!outBio) {
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to create output BIO");
    }

    if (PEM_write_bio_X509_REQ(outBio, req) != 1) {
        BIO_free(outBio);
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to write CSR to PEM");
    }

    char* data;
    long len = BIO_get_mem_data(outBio, &data);
    std::string result(data, len);

    BIO_free(outBio);
    X509_REQ_free(req);
    EVP_PKEY_free(pkey);

    return result;
}

std::string CSR::extractPublicKey(const std::string& csrPEM) {
    BIO* bio = BIO_new_mem_buf(csrPEM.data(), static_cast<int>(csrPEM.size()));
    if (!bio) {
        throw std::runtime_error("Failed to create BIO from CSR PEM");
    }

    X509_REQ* req = PEM_read_bio_X509_REQ(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!req) {
        throw std::runtime_error("Failed to parse CSR from PEM");
    }

    // Extract public key
    EVP_PKEY* pkey = X509_REQ_get_pubkey(req);
    X509_REQ_free(req);

    if (!pkey) {
        throw std::runtime_error("Failed to extract public key from CSR");
    }

    BIO* keyBio = BIO_new(BIO_s_mem());
    if (!keyBio) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to create BIO for public key");
    }

    if (PEM_write_bio_PUBKEY(keyBio, pkey) != 1) {
        BIO_free(keyBio);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to write public key to PEM");
    }

    char* data;
    long len = BIO_get_mem_data(keyBio, &data);
    std::string result(data, len);

    BIO_free(keyBio);
    EVP_PKEY_free(pkey);

    return result;
}

bool CSR::validate(const std::string& csrPEM) {
    BIO* bio = BIO_new_mem_buf(csrPEM.data(), static_cast<int>(csrPEM.size()));
    if (!bio) {
        return false;
    }

    X509_REQ* req = PEM_read_bio_X509_REQ(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!req) {
        return false;
    }

    int valid = X509_REQ_verify(req, X509_REQ_get_pubkey(req));
    X509_REQ_free(req);

    return valid == 1;
}

} // namespace crypto
} // namespace fabric