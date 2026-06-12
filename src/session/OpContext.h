#ifndef vHSM_OP_CONTEXT_H
#define vHSM_OP_CONTEXT_H

/// OpContext is the abstract base class for operation-specific contexts
/// used by the session layer (for example: SignContext, VerifyContext,
/// EncryptContext, etc.). An OpContext instance encapsulates ephemeral
/// state associated with a multi-step cryptographic operation and is meant
/// to be stored and passed around polymorphically.
///
/// Design constraints:
/// - Non-copyable to avoid accidental duplication of operation state.
/// - Moveable to allow transfer of ownership when session state is relocated.
class OpContext {
public:
    OpContext() = default;
    virtual ~OpContext() = default;

    /// Non-copyable, moveable (Rule-of-five simplified)
    OpContext(const OpContext&) = delete;
    OpContext& operator=(const OpContext&) = delete;
    OpContext(OpContext&&) noexcept = default;
    OpContext& operator=(OpContext&&) noexcept = default;
};
#endif