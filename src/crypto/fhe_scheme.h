#ifndef VHSM_CRYPTO_FHE_SCHEME
#define VHSM_CRYPTO_FHE_SCHEME
/**
 * fhe_scheme.hpp (Research perspective)
 * ──────────────
 * Core types and interface for Gentry's Ideal-Lattice FHE scheme  (E₁/E₂/E₃).
 *
 * The implementation is structured in three layers that mirror the paper:
 *
 *   Layer 1  –  SchemeE1  (§3):  homomorphic for shallow circuits.
 *   Layer 2  –  SchemeE2  (§4):  E₁ with the two tweaks; lowers decryption depth.
 *   Layer 3  –  SchemeE3  (§5):  E₂ + "squashing" transformation; bootstrappable.
 *
 * For clarity and practicality the implementation uses small toy parameters
 * (n ≈ 8–16).  Production parameters would require n ≈ λ² with λ ≈ 80+.
 *
 * References: Gentry STOC'09, §§1–6; Definitions 1–14, Theorems 1–11.
 */

#include "gentry_polynomial.h"
#include "gentry_ideal_lattice.h"
#include "matrix_utils.h"

#include <vector>
#include <random>
#include <memory>
#include <functional>
#include <stdexcept>
#include <cstdint>
#include <string>

namespace vhsm::crypto::fhe {

//  Plaintext
/// A single-bit plaintext (0 or 1), matching P = {0,1} mod B_I (§4.2).
using Plaintext = int;


//  Ciphertext
/**
 * A ciphertext is an element of R mod B^pk_J.
 * Concretely stored as an n-dimensional integer vector (= coefficient vector
 * of the polynomial ring element after reduction mod B^pk_J).
 *
 * §1.2: "a ciphertext ψ has the form v + x where v ∈ J and x encodes π".
 */
struct Ciphertext {
    std::vector<long long> data;   ///< Coefficient vector, length = n.
    int                    level;  ///< Circuit level (for leveled FHE).

    explicit Ciphertext(int n = 0, int lvl = 0)
        : data(n, 0LL), level(lvl) {}

    explicit Ciphertext(std::vector<long long> d, int lvl = 0)
        : data(std::move(d)), level(lvl) {}

    int  dim()     const { return (int)data.size(); }
    bool is_zero() const {
        for (auto x : data) if (x != 0) return false;
        return true;
    }
};

//  Parameters
/**
 * Scheme parameters.  For a real deployment, these are derived from the
 * security parameter λ.  Here small values allow unit-testing.
 *
 * §3.4 / §6: rEnc, rDec, γ_Mult(R), lattice dimension n.
 */
struct FHEParams {
    int    n;           ///< Ring dimension (degree of f).
    long long q;        ///< Coefficient modulus for the public-key ideal J.
    double sigma;       ///< Gaussian noise standard deviation for Samp₁.
    long long s_val;    ///< The short element s ∈ I  (concretely s = 2).
    int    gamma_set;   ///< |τ| = γ_set(n)  for E₃ squashing (§5.2).
    int    gamma_subset;///< |S| = γ_subset(n) for E₃ squashing (§5.2).

    /// Toy parameters for n-bit ring.  NOT secure, for testing only.
    static FHEParams toy(int n = 8) {
        FHEParams p;
        p.n            = n;
        p.q            = (1LL << (2 * n));   // large enough public modulus
        p.sigma        = 1.0;                // small Gaussian noise
        p.s_val        = 2LL;
        p.gamma_set    = 2 * n;
        p.gamma_subset = n / 2;
        return p;
    }
};

//  Public Key
struct PublicKey {
    int       n;
    Polynomial f;          ///< Modulus polynomial of R = Z[x]/f(x).
    IMatrix   B_I;         ///< Basis of ideal I  (plaintext modulus).
    IMatrix   B_J_pk;      ///< HNF (public) basis of ideal J.
    Matrix    B_J_pk_inv;  ///< Pre-computed B_J_pk^{-1}.
    long long det_I;       ///< det(I) = [R:I], size of plaintext space.

    // E₃ extension: squashing set τ  (§5.2).
    std::vector<std::vector<long long>> tau; ///< γ_set random vectors in J^{-1} mod B_I.
};

//  Secret Key
struct SecretKey {
    int    n;
    IMatrix B_J_sk;        ///< "Good" short basis of J  (§3.4).
    Matrix  B_J_sk_inv;    ///< Pre-computed B_J_sk^{-1}.

    // E₃ extension: sparse incidence matrix M  (§5.2).
    std::vector<std::vector<int>> M;  ///< γ_subset × γ_set binary matrix.
};

//  SchemeE1  –  §3  (Initial Construction)
class SchemeE1 {
public:
    explicit SchemeE1(FHEParams params, uint64_t seed = 42);

    // §3.1 KeyGen
    /**
     * KeyGen(R, B_I):
     *   • Runs IdealGen to produce (B^sk_J, B^pk_J).
     *   • Returns (sk, pk).
     */
    std::pair<SecretKey, PublicKey> key_gen();

    // §3.1 Encrypt
    /**
     * Encrypt(pk, π):
     *   ψ' ← Samp(π, B_I, R, B^pk_J)
     *   ψ  ← ψ' mod B^pk_J
     */
    Ciphertext encrypt(const PublicKey& pk, Plaintext pi);

    // §3.1 Decrypt
    /**
     * Decrypt(sk, ψ):
     *   π ← (ψ mod B^sk_J) mod B_I
     *
     * §4.1 Tweak 1 / Tweak 2 variants optionally used.
     */
    Plaintext decrypt(const SecretKey& sk, const PublicKey& pk,
                    const Ciphertext& ct);

    // §3.1 Evaluate (homomorphic Add / Mult)
    /**
     * Add(pk, ψ₁, ψ₂) = ψ₁ + ψ₂ mod B^pk_J
     * §3.1, Definition 6 (Generalized Circuit).
     */
    Ciphertext eval_add(const PublicKey& pk,
                        const Ciphertext& c1, const Ciphertext& c2);

    /**
     * Mult(pk, ψ₁, ψ₂) = ψ₁ × ψ₂ mod B^pk_J
     * Multiplication in R = Z[x]/f(x), then reduced mod J.
     */
    Ciphertext eval_mul(const PublicKey& pk,
                        const Ciphertext& c1, const Ciphertext& c2);

    /**
     * NAND gate:  NAND(a, b)  = 1 - a·b   (for {0,1} plaintexts).
     * Used as the universal gate for bootstrapping (§2).
     */
    Ciphertext eval_nand(const PublicKey& pk,
                        const Ciphertext& c1, const Ciphertext& c2);

    // accessors
    const FHEParams& params() const { return params_; }
    const Polynomial& f()     const { return f_; }

protected:
    FHEParams    params_;
    Polynomial   f_;      ///< Ring modulus.
    Polynomial   B_I_gen_;///< Generator of ideal I (s = 2·e₁ → I = (2)).
    std::mt19937_64 rng_;

    // IdealGen: produce public/secret J bases
    /**
     * IdealGen(R, B_I):
     *   Generates a random "good" secret basis B^sk_J and its HNF B^pk_J
     *   such that I + J = R  (i.e., gcd(I,J) = R).
     */
    void ideal_gen(const IMatrix& B_I, IMatrix& B_J_sk, IMatrix& B_J_pk);

    // Samp:  sample from coset  π + I
    /**
     * Samp(π, B_I, R, B^pk_J):
     *   r ← Samp₁(R);   output π + r × s  (mod B^pk_J representation).
     *
     * §3.2: s ∈ I with (s) coprime to J; concretely s = 2 when I = (2·e₁).
     */
    std::vector<long long> samp(const std::vector<long long>& pi_vec,
                                const PublicKey& pk);

    // Reduce mod public key basis
    std::vector<long long> reduce_mod_pk(const std::vector<long long>& v,
                                        const PublicKey& pk);

    // Polynomial ring multiplication of ciphertext vectors
    std::vector<long long> ring_mul_vecs(const std::vector<long long>& a,
                                        const std::vector<long long>& b,
                                        const PublicKey& pk);
};

//  SchemeE2  –  §4  (Tweaked scheme, lower decryption depth)
class SchemeE2 : public SchemeE1 {
public:
    explicit SchemeE2(FHEParams params, uint64_t seed = 42)
        : SchemeE1(std::move(params), seed) {}

    /**
     * Decrypt with Tweak 1 (§4.1):
     *   Ensures |(B^sk_J)^{-1}·ψ|_∞ < 1/4 so rounding needs only 2 bits
     *   of precision (Lemma 2).
     *
     * The decryption formula is the same; the tweak narrows CE to B(rDec/2).
     */
    Plaintext decrypt_tweak1(const SecretKey& sk, const PublicKey& pk,
                            const Ciphertext& ct);
};

//  SchemeE3  –  §5  (Squashed decryption; bootstrappable)
class SchemeE3 : public SchemeE2 {
public:
    explicit SchemeE3(FHEParams params, uint64_t seed = 42)
        : SchemeE2(std::move(params), seed) {}

    // §5.2 KeyGen (extended with τ, M)
    /**
     * Runs E₂ KeyGen, then SplitKey to produce τ and M.
     * Public key gains τ; secret key gains M.
     */
    std::pair<SecretKey, PublicKey> key_gen_e3();

    // §5.2 Encrypt (extended with ExpandCT)
    /**
     * Encrypt(pk, π):
     *   ψ* ← E₂.Encrypt(pk*, π)
     *   Appends ci = τᵢ × ψ* mod B_I  for i ∈ [γ_set]  (ExpandCT, §5.2).
     */
    Ciphertext encrypt_e3(const PublicKey& pk, Plaintext pi);

    // §5.2 Decrypt (squashed; adds only γ_subset vectors)
    /**
     * Decrypt(sk, ψ):
     *   Steps 0–3 from §5.2, adding only γ_subset(n) vectors.
     */
    Plaintext decrypt_e3(const SecretKey& sk, const PublicKey& pk,
                        const Ciphertext& ct);

    // §5.1 SplitKey
    /**
     * SplitKey(sk*, pk*):
     *   Generates τ (γ_set random vectors with hidden sparse subset summing to
     *   v^{sk*}_J) and M (γ_subset × γ_set binary incidence matrix).
     */
    void split_key(const SecretKey& sk, const PublicKey& pk,
                std::vector<std::vector<long long>>& tau_out,
                std::vector<std::vector<int>>&        M_out);

private:
    /// Helper: compute v^sk_J  (short vector in J^{-1}).
    std::vector<long long> compute_vsk(const SecretKey& sk);

    /// Helper: ExpandCT step — ci = τᵢ × ψ* mod B_I.
    std::vector<std::vector<long long>>
    expand_ct(const PublicKey& pk, const std::vector<long long>& psi_star);
};

//  Bootstrapping (Recrypt)  –  §2, Theorem 1
/**
 * Recrypt(pk₂, D_E, {sk₁ⱼ}, ψ₁):
 *   Evaluates the decryption circuit D_E homomorphically under pk₂.
 *   Returns ψ₂ = Enc_{pk₂}(Dec_{sk₁}(ψ₁)).
 *
 * This refreshes the ciphertext, replacing the old error vector with a
 * fresh short one.  This is the key step that makes the scheme fully
 * homomorphic via Theorem 1.
 *
 * §2: "we decrypt the ciphertext, but homomorphically!"
 */
Ciphertext recrypt(SchemeE3& scheme,
                const PublicKey&  pk2,
                const SecretKey&  sk1,
                const PublicKey&  pk1,
                const Ciphertext& psi1);

//  Circuit evaluation helpers
/// Evaluate a boolean function given as a truth-table (2^arity entries).
Ciphertext eval_boolean(SchemeE1& scheme, const PublicKey& pk,
                        const std::vector<Ciphertext>& inputs,
                        const std::vector<int>& truth_table);

/// Evaluate a NAND tree homomorphically.
Ciphertext eval_nand_tree(SchemeE1& scheme, const PublicKey& pk,
                        const Ciphertext& a, const Ciphertext& b);

} // namespace fhe
#endif // VHSM_CRYPTO_FHE_SCHEME