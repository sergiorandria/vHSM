#ifndef VHSM_ADMIN_H
#define VHSM_ADMIN_H

#include <cstdlib>
#include <exception>
#include <string>
#include <iostream>
#include "../core/types.h"

// Retrieve the admin ID from environment variables.
// Returns "admin" as a safe default if VHSM_ADMIN_ID is not set.
inline std::string get_admin_id() noexcept {
    try {
        const char* id = std::getenv("VHSM_ADMIN_ID");
        if (id != nullptr && id[0] != '\0') {
            return std::string(id);
        }
        return "admin";
    } catch (const std::exception& e) {
        std::cerr << "get_admin_id: " << e.what() << std::endl;
        return "admin";
    }
}

// Retrieve admin hashed password from environment variables.
// Returns empty string if VHSM_ADMIN_PASS is not set.
inline std::string get_admin_hpass() noexcept {
    try {
        const char* hpass = std::getenv("VHSM_ADMIN_PASS");
        if (hpass != nullptr) {
            return std::string(hpass);
        }
        return "";
    } catch (const std::exception& e) {
        std::cerr << "get_admin_hpass: " << e.what() << std::endl;
        return "";
    }
}

#endif // VHSM_ADMIN_H