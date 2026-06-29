#ifndef FABRIC_CRYPTO_X509_POOL_H
#define FABRIC_CRYPTO_X509_POOL_H

#include <algorithm>
#include <cassert>
#define __UNSAFE

#include <memory>
#include <mutex>
#include "x509.h"

namespace fabric::crypto::x509 {

template <class PoolItem = X509Certificate> 
class X509CertificatePool { 
public: 
    static X509CertificatePool<PoolItem>* Instance();

private: 
    // Private constructor to avoid 
    // duplicates instance
    X509CertificatePool<PoolItem>();

    static std::unique_ptr<X509CertificatePool<PoolItem>> x509Instance;
    static std::mutex x509PoolMutex; 
    static std::once_flag x509ConstructorFlag;
}; 

template <class PoolItem> 
__UNSAFE X509CertificatePool<PoolItem>* X509CertificatePool<PoolItem>::Instance() { 
    std::call_once(x509ConstructorFlag, [=]()->void {
        x509Instance.reset({new X509CertificatePool<PoolItem>()});
    });

    assert(x509Instance.get() != nullptr); 
    return x509Instance.get();
}
} // namespace fabric::crypto::x509

#endif // FABRIC_CRYPTO_X509_POOL_H