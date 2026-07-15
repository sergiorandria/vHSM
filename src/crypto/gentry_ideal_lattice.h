#ifndef VHSM_CRYPTO_GENTRY_IDEAL_LATTICE
#define VHSM_CRYPTO_GENTRY_IDEAL_LATTICE
/**
 * ideal_lattice.hpp (Research perspective)
 * ─────────────────
 * Ideal lattice basis operations for Gentry's FHE scheme.
 *
 * An ideal  I ⊆ R = Z[x]/f(x)  is represented by an n×n integer matrix
 * whose columns span I as a Z-lattice.  Two distinguished bases are used:
 *
 *   B_I   – fixed public basis of the "small" ideal I  (used for plaintext
 *            space and for the Add/Mult gate modular arithmetic).
 *
 *   B^pk_J – HNF (Hermite Normal Form) basis of J, the public key ideal.
 *   B^sk_J – a "good" (short) basis of J, the secret key.
 *
 * Key operation:  t mod B  where mod is defined as the unique representative
 * in the half-open parallelepiped P(B) = { B·x : x ∈ [-½, ½)^n }.
 *
 * Reference: Gentry STOC'09, §3.3 – §3.4, Lemmas 1–4, Definitions 6–9.
 */

#include "gentry_polynomial.h"

#include <cmath>
#include <functional>
#include <random>
#include <vector>

namespace vhsm::crypto::fhe
{

using Matrix = std::vector<std::vector<double>>;     // n×n real matrix
using IMatrix = std::vector<std::vector<long long>>; // n×n integer matrix

//  Small linear-algebra helpers
namespace linalg
{

/// Return n×n identity matrix.
inline IMatrix identity(int n)
{
    IMatrix I(n, std::vector<long long>(n, 0LL));
    for (int i = 0; i < n; ++i)
    {
        I[i][i] = 1LL;
    }
    return I;
}

/// Matrix–vector product (integer).
inline std::vector<long long> matvec(const IMatrix& A, const std::vector<long long>& v)
{
    int n = (int) A.size();
    std::vector<long long> res(n, 0LL);
    for (int i = 0; i < n; ++i)
    {
        for (int j = 0; j < n; ++j)
        {
            res[i] += A[i][j] * v[j];
        }
    }
    return res;
}

/// Matrix–vector product (real).
inline std::vector<double> matvec(const Matrix& A, const std::vector<double>& v)
{
    int n = (int) A.size();
    std::vector<double> res(n, 0.0);
    for (int i = 0; i < n; ++i)
    {
        for (int j = 0; j < n; ++j)
        {
            res[i] += A[i][j] * v[j];
        }
    }
    return res;
}

/// Round each entry of a real vector to the nearest integer.
inline std::vector<long long> round_vec(const std::vector<double>& v)
{
    std::vector<long long> res(v.size());
    for (std::size_t i = 0; i < v.size(); ++i)
    {
        res[i] = (long long) std::round(v[i]);
    }
    return res;
}

/// Euclidean norm of an integer vector.
inline double l2_norm(const std::vector<long long>& v)
{
    double s = 0.0;
    for (auto x : v)
    {
        s += (double) x * (double) x;
    }
    return std::sqrt(s);
}

/// l∞ norm of integer vector.
inline long long linf_norm(const std::vector<long long>& v)
{
    long long m = 0;
    for (auto x : v)
    {
        long long a = x < 0 ? -x : x;
        if (a > m)
        {
            m = a;
        }
    }
    return m;
}

/// Add two integer vectors.
inline std::vector<long long> add(const std::vector<long long>& a, const std::vector<long long>& b)
{
    int n = (int) a.size();
    std::vector<long long> r(n);
    for (int i = 0; i < n; ++i)
    {
        r[i] = a[i] + b[i];
    }
    return r;
}

/// Subtract two integer vectors.
inline std::vector<long long> sub(const std::vector<long long>& a, const std::vector<long long>& b)
{
    int n = (int) a.size();
    std::vector<long long> r(n);
    for (int i = 0; i < n; ++i)
    {
        r[i] = a[i] - b[i];
    }
    return r;
}

/// Scale integer vector by scalar.
inline std::vector<long long> scale(const std::vector<long long>& v, long long s)
{
    std::vector<long long> r(v.size());
    for (std::size_t i = 0; i < v.size(); ++i)
    {
        r[i] = v[i] * s;
    }
    return r;
}

} // namespace linalg

//  Rotation basis — principal ideal (v) in Z[x]/f(x)
/**
 * Builds the n×n rotation matrix whose columns are
 *   v, x·v mod f, x²·v mod f, …, x^{n-1}·v mod f
 * (each stored as a column of integer coefficients).
 * Gentry §3.3: "the rotation basis of the ideal lattice (v)".
 */
IMatrix rotation_basis(const Polynomial& v, const Polynomial& f);

//  Basis "mod" operation:  t mod B  →  unique representative in P(B)
/**
 * Given a *real* inverse B^{-1} and integer vector t, computes
 *   t mod B  =  t - B · round(B^{-1} · t)
 * as per Definition in §3.3 and Lemma 1.
 *
 * The caller pre-computes B_inv = B^{-1} for efficiency.
 */
std::vector<long long> vec_mod_basis(const std::vector<long long>& t, const IMatrix& B, const Matrix& B_inv);

//  rDec  =  1 / (2 · ‖(B^{sk}_J)^{-1}‖)   (Lemma 1)
double compute_rDec(const Matrix& B_sk_inv);

//  Polynomial ↔ vector conversions (coefficient vector representation)
inline std::vector<long long> poly_to_vec(const Polynomial& p, int n)
{
    std::vector<long long> v(n, 0LL);
    for (int i = 0; i < n && i <= p.degree(); ++i)
    {
        v[i] = p[i];
    }
    return v;
}

inline Polynomial vec_to_poly(const std::vector<long long>& v)
{
    std::vector<Polynomial::Coeff> c(v.begin(), v.end());
    return Polynomial(std::move(c));
}

//  Simple Gaussian-integer sampler  (Samp_1 in §3.2)
/**
 * Samples a random vector r in Z^n with each coordinate drawn from
 * N(0, sigma^2) rounded to the nearest integer.  Used as Samp_1(R).
 */
std::vector<long long> sample_gaussian(int n, double sigma, std::mt19937_64& rng);

/**
 * Samples a random vector uniformly from  [-bound, bound]^n ∩ Z^n.
 */
std::vector<long long> sample_uniform(int n, long long bound, std::mt19937_64& rng);

} // namespace vhsm::crypto::fhe
#endif