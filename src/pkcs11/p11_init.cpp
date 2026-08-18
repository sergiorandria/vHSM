#include "pkcs11_internal.h"
#include "pkcs11.h"
#include "pkcs11_types.h"

#include "../keystore/slot.h"
#include "../keystore/token.h"

#include <cstring>

namespace vhsm::pkcs11 {

static void ensure_default_token() {
    auto& sm = vhsm::session::SlotManager::get_instance();
    if (!sm.get_slot(0)) {
        auto slot = std::make_shared<vhsm::keystore::Slot>(0);
        auto tok  = std::make_shared<vhsm::keystore::Token>("vHSM Software Token", "vhsm-token-0");
        slot->insert_token(tok);
        sm.register_slot(0);
    }
}

CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
    if (g_initialized) return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    if (pInitArgs != nullptr) {
        auto* args = static_cast<CK_C_INITIALIZE_ARGS_PTR>(pInitArgs);
        if (args->flags & CKF_OS_LOCKING_OK) {
            // we always support locking; fine
        }
    }
    ensure_default_token();
    g_initialized = true;
    return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved) {
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (pReserved != nullptr) return CKR_ARGUMENTS_BAD;
    g_initialized = false;
    vhsm::session::SlotManager::get_instance().reset();
    return CKR_OK;
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo) {
    if (!pInfo) return CKR_ARGUMENTS_BAD;
    std::memset(pInfo, 0, sizeof(CK_INFO));
    pInfo->cryptokiVersion.major = 2;
    pInfo->cryptokiVersion.minor = 40;
    pInfo->libraryVersion.major  = 1;
    pInfo->libraryVersion.minor  = 0;
    const char* m = "vHSM";
    const char* d = "vHSM PKCS#11 Module";
    std::memcpy(pInfo->manufacturerID, m, std::min(std::strlen(m), sizeof(pInfo->manufacturerID)));
    std::memcpy(pInfo->libraryDescription, d, std::min(std::strlen(d), sizeof(pInfo->libraryDescription)));
    return CKR_OK;
}

} // namespace vhsm::pkcs11
