#ifndef FABRIC_CRYPTO_CLASS_H
#define FABRIC_CRYPTO_CLASS_H

#include <string>

namespace fabric::crypto { 
class ICryptoClass { 
protected: 
    virtual std::string Representation() const = 0;
};
} // fabric::crypto

#endif // FABRIC_CRYPTO_CLASS_H