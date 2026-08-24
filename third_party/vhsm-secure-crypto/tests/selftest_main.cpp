#include "vhsm/scrypto/scrypto.h"
#include <iostream>
int main() {
  try {
    bool ok = vhsm::scrypto::selftest(true);
    std::cout << "vhsm-secure-crypto selftest: " << (ok ? "PASS" : "FAIL")
              << " version " << vhsm::scrypto::version() << "\n";
    return ok ? 0 : 1;
  } catch (const std::exception &e) {
    std::cerr << "selftest exception: " << e.what() << "\n";
    return 1;
  }
}
