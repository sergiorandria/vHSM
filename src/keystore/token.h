#ifndef VHSM_SESSION_TOKEN_H
#define VHSM_SESSION_TOKEN_H

#include <string>
#include <cstdint>
#include "../keystore/object_store.h" // Inclusion of Phase 2 ObjectStore component

namespace vhsm {

/**
 * @enum LoginState
 * @brief Represents the authentication or access control state of a cryptographic token.
 *
 * Defines the current level of privilege and restriction applied to operations targetting 
 * the underlying object store, conforming to the PKCS#11 architecture.
 */
enum class LoginState {
    PUBLIC,       /**< No user logged in. Only public objects (certificates, public keys) are accessible. */
    USER_LOGGED,  /**< Standard Crypto User logged in. Full access to private/secret keys for signing. */
    SO_LOGGED     /**< Security Officer logged in. Administrative rights active (destructive initialization). */
};

/**
 * @class token
 * @brief Represents a virtual cryptographic token containing keys and certificates within a slot.
 *
 * The token class acts as the logical repository for cryptographic objects. It enforces 
 * access controls via its current LoginState and encapsulates an isolated, thread-safe ObjectStore.
 * * @note This class is non-copyable to prevent duplicating cryptographic key stores in RAM.
 */
class token {
public:
    /**
     * @brief Constructs a virtual token with a descriptive display label.
     * @param label The human-readable label for the token (e.g., "Production-token-1").
     */
    explicit token(std::string label);

    /**
     * @brief Default destructor. Ensures safe release of internal cryptographic assets.
     */
    ~token() = default;

    // Delete copy operations to ensure strict uniqueness of the internal cryptographic store.
    token(const token&) = delete;
    token& operator=(const token&) = delete;

    /**
     * @brief Retrieves the token's display label.
     * @return std::string The token label string.
     */
    std::string get_label() const { return label_; }

    /**
     * @brief Retrieves the hardware emulation model identity string.
     * @return std::string The model identifier.
     */
    std::string get_model() const { return model_; }

    /**
     * @brief Retrieves the hardcoded virtual serial number.
     * @return std::string The serial number string.
     */
    std::string get_serial_number() const { return serial_number_; }

    /**
     * @brief Gets the current authentication login state.
     * @return LoginState The current privilege tier.
     */
    LoginState get_login_state() const { return login_state_; }

    /**
     * @brief Dynamically alters the token authentication state.
     * @param state The new access level to enforce.
     */
    void set_login_state(LoginState state) { login_state_ = state; }

    /**
     * @brief Convenience check to determine if a regular cryptographic user is logged in.
     * @return true if USER_LOGGED tier is active, false otherwise.
     */
    bool is_user_logged() const { return login_state_ == LoginState::USER_LOGGED; }

    /**
     * @brief Convenience check to determine if a security officer administrator is logged in.
     * @return true if SO_LOGGED tier is active, false otherwise.
     */
    bool is_so_logged() const { return login_state_ == LoginState::SO_LOGGED; }

    /**
     * @brief Provides direct mutable access to the internal object memory pool.
     * @return keystore::ObjectStore& Reference to the isolated token storage instance.
     */
    keystore::ObjectStore& get_store() { return store_; }
    
    /**
     * @brief Provides read-only access to the internal object memory pool.
     * @return const keystore::ObjectStore& Constant reference to the isolated token storage instance.
     */
    const keystore::ObjectStore& get_store() const { return store_; }

    /**
     * @brief Computes and returns standard PKCS#11 capability flags for this token.
     * @return uint64_t Bitmask containing CKF_RNG, CKF_LOGIN_REQUIRED, etc.
     */
    uint64_t get_flags() const;

private:
    std::string label_;
    std::string model_;
    std::string serial_number_;
    LoginState login_state_;

    /**
     * @brief Isolated instance of ObjectStore managing handles and security contexts for keys.
     */
    keystore::ObjectStore store_; 
};

} // namespace vhsm

#endif // VHSM_SESSION_TOKEN_H