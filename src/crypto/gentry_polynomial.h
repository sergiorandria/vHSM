#ifndef VHMS_CRYPTO_GENTRY_POLYNOMIAL 
#define VHMS_CRYPTO_GENTRY_POLYNOMIAL
/**
 * polynomial.hpp (Research perspective about homomorphic encryption)
 * ─────────────
 * Arithmetic in the ring  R = Z[x] / f(x)
 * where f(x) is a monic polynomial supplied at construction time.
 *
 * All arithmetic (add, sub, mul) is performed over Z (no modular
 * reduction of *coefficients* here – that is the job of the ideal /
 * lattice layer above).  Reduction modulo f(x) IS performed after
 * every multiplication so that the result stays degree < n.
 *
 * Based on:
 *   Craig Gentry, "Fully Homomorphic Encryption Using Ideal Lattices",
 *   STOC 2009, Sections 3.3 – 3.4.
 */

#include <vector>
#include <stdexcept>
#include <ostream>
#include <cassert>
#include <numeric>

namespace vhsm::crypto::fhe {

class Polynomial {
public:
    using Coeff = long long;

    // constructors
    Polynomial() = default;

    /// Build from coefficient vector (index = power, little-endian).
    explicit Polynomial(std::vector<Coeff> coeffs)
        : coeffs_(std::move(coeffs)) { trim(); }

    /// Constant polynomial.
    explicit Polynomial(Coeff c) : coeffs_({c}) { trim(); }

    /// Zero polynomial of the given degree.
    static Polynomial zero(std::size_t deg = 0) {
        return Polynomial(std::vector<Coeff>(deg + 1, 0LL));
    }

    // properties
    int  degree()  const { return coeffs_.empty() ? -1 : (int)coeffs_.size() - 1; }
    bool is_zero() const { return coeffs_.empty(); }
    std::size_t size() const { return coeffs_.size(); }

    Coeff operator[](std::size_t i) const {
        return i < coeffs_.size() ? coeffs_[i] : 0LL;
    }
    Coeff& operator[](std::size_t i) {
        if (i >= coeffs_.size()) coeffs_.resize(i + 1, 0LL);
        return coeffs_[i];
    }

    const std::vector<Coeff>& coefficients() const { return coeffs_; }

    // arithmetic (plain Z[x], no reduction mod f)
    Polynomial operator+(const Polynomial& o) const {
        std::size_t n = std::max(size(), o.size());
        std::vector<Coeff> res(n, 0LL);
        for (std::size_t i = 0; i < n; ++i)
            res[i] = (*this)[i] + o[i];
        return Polynomial(std::move(res));
    }

    Polynomial operator-(const Polynomial& o) const {
        std::size_t n = std::max(size(), o.size());
        std::vector<Coeff> res(n, 0LL);
        for (std::size_t i = 0; i < n; ++i)
            res[i] = (*this)[i] - o[i];
        return Polynomial(std::move(res));
    }

    Polynomial operator-() const {
        std::vector<Coeff> res(size());
        for (std::size_t i = 0; i < size(); ++i) res[i] = -coeffs_[i];
        return Polynomial(std::move(res));
    }

    /// Plain multiplication (result degree up to deg(a)+deg(b)).
    Polynomial operator*(const Polynomial& o) const {
        if (is_zero() || o.is_zero()) return Polynomial();
        std::size_t n = size() + o.size() - 1;
        std::vector<Coeff> res(n, 0LL);
        for (std::size_t i = 0; i < size(); ++i)
            for (std::size_t j = 0; j < o.size(); ++j)
                res[i + j] += coeffs_[i] * o.coeffs_[j];
        return Polynomial(std::move(res));
    }

    Polynomial& operator+=(const Polynomial& o) { *this = *this + o; return *this; }
    Polynomial& operator-=(const Polynomial& o) { *this = *this - o; return *this; }
    Polynomial& operator*=(const Polynomial& o) { *this = *this * o; return *this; }

    /// Scalar multiplication.
    Polynomial operator*(Coeff c) const {
        std::vector<Coeff> res(size());
        for (std::size_t i = 0; i < size(); ++i) res[i] = coeffs_[i] * c;
        return Polynomial(std::move(res));
    }

    // reduction mod f(x)
    /**
     * Reduce *this modulo the monic polynomial f of degree n.
     * Uses plain polynomial division; suitable for small n.
     */
    Polynomial reduce_mod(const Polynomial& f) const;

    /**
     * Multiply and immediately reduce mod f.
     * Gentry §3.3: ring operations in R = Z[x]/f(x).
     */
    Polynomial ring_mul(const Polynomial& o, const Polynomial& f) const {
        return (*this * o).reduce_mod(f);
    }

    // coefficient reduction
    /// Reduce every coefficient modulo q, centred in (-q/2, q/2].
    Polynomial coeff_mod(Coeff q) const;

    // norm / geometry
    /// Euclidean (l2) norm of coefficient vector.
    double l2_norm() const;

    /// l∞ norm.
    Coeff linf_norm() const;

    // equality / output
    bool operator==(const Polynomial& o) const { return coeffs_ == o.coeffs_; }
    bool operator!=(const Polynomial& o) const { return !(*this == o); }

    friend std::ostream& operator<<(std::ostream& os, const Polynomial& p);

private:
    std::vector<Coeff> coeffs_;   // little-endian: coeffs_[i] is coeff of x^i

    void trim() {
        while (!coeffs_.empty() && coeffs_.back() == 0)
            coeffs_.pop_back();
    }
};

/// Monic cyclotomic-like polynomial  x^n + 1  (good γ_Mult, cf. Theorem 9).
inline Polynomial make_f_xn_plus_1(int n) {
    std::vector<Polynomial::Coeff> c(n + 1, 0LL);
    c[0] = 1;          // constant +1
    c[n] = 1;          // x^n
    return Polynomial(std::move(c));
}

/// Monic polynomial  x^n - 1.
inline Polynomial make_f_xn_minus_1(int n) {
    std::vector<Polynomial::Coeff> c(n + 1, 0LL);
    c[0] = -1;
    c[n] =  1;
    return Polynomial(std::move(c));
}
}  // namespace fhe
#endif 