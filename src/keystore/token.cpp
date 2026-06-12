#include "token.h"
#include <utility>

/**
 * @brief constantes de masque de bits standard de PKCS#11
 * */
constexpr uint64_t CKF_RNG                = 0x00000001; 
constexpr uint64_t CKF_LOGIN_REQUIRED     = 0x00000004; 
constexpr uint64_t CKF_USER_PIN_INITIALIZED = 0x00000008; 
constexpr uint64_t CKF_token_INITIALIZED  = 0x00000400; 

namespace vhsm {

token::token(std::string label)
    : label_(std::move(label)),
      model_("vHSM Cryptographic Engine v2"),
      serial_number_("69-420-vHSM-SN"),
      login_state_(LoginState::PUBLIC) {}

uint64_t token::get_flags() const {
    uint64_t flags = 0;

    flags |= CKF_RNG;
    flags |= CKF_LOGIN_REQUIRED;
    flags |= CKF_USER_PIN_INITIALIZED;
    flags |= CKF_token_INITIALIZED;

    return flags;
}

} // namespace vhsm