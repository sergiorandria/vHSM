#ifndef FABRIC_CRYPTO_X509_POOL_H
#define FABRIC_CRYPTO_X509_POOL_H

#include <algorithm>
#include <cassert>
#include <memory>
#include <mutex>
#include <stdexcept>

#include "x509.h"

namespace fabric::crypto::x509 {

template <class PoolItem = X509Certificate> 
class X509CertificatePool { 
public: 
    static X509CertificatePool<PoolItem>* Instance();

    void createX509CertificatePool(std::vector<PoolItem> items); 

private: 
    // Private constructor to avoid 
    // duplicates instance
    X509CertificatePool<PoolItem>();

    std::vector<PoolItem> x509CertificateElements; 

    static std::unique_ptr<X509CertificatePool<PoolItem>> x509CertInstance;
    static std::mutex x509CertPoolMutex; 
    static std::once_flag x509CertConstructorFlag;
}; 

template <class PoolItem>
X509CertificatePool<PoolItem>* X509CertificatePool<PoolItem>::Instance() { 
    std::call_once(x509CertConstructorFlag, [=]()->void {
        x509CertInstance.reset({new X509CertificatePool<PoolItem>()});
    });

    // Ensure x509CertInstance integrity 
    // before returning
    assert(x509CertInstance.get() != nullptr); 
    return x509CertInstance.get();
}

template <class PoolItem> 
void X509CertificatePool<PoolItem>::createX509CertificatePool(std::vector<PoolItem> items) { 
    for(auto item: items) {
        if (!item.isValid()) {
            throw std::runtime_error("Invalid X509 certificate");
        }

        this->x509CertificateElements.push_back(item);
    }
}
} // namespace fabric::crypto::x509

#endif // FABRIC_CRYPTO_X509_POOL_H