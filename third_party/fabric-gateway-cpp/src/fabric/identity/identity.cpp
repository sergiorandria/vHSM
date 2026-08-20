#include "../../../include/fabric/identity/identity.h"

namespace fabric {
namespace identity {

Identity::Identity(const std::string &mspId, const std::string &cert,
                   const std::string &key)
    : mspId_(mspId), certificate_(cert), privateKey_(key) {}

const std::string &Identity::getMSPID() const { return mspId_; }

const std::string &Identity::getCertificate() const { return certificate_; }

const std::string &Identity::getPrivateKey() const { return privateKey_; }

bool Identity::isValid() const {
  return !mspId_.empty() && !certificate_.empty() && !privateKey_.empty();
}

} // namespace identity
} // namespace fabric