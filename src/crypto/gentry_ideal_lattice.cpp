#include "gentry_ideal_lattice.h"

#include <stdexcept>
#include <cmath>

namespace vhsm::crypto::fhe {

//  rotation_basis
IMatrix rotation_basis(const Polynomial& v, const Polynomial& f) {
    int n = f.degree();
    if (n <= 0) throw std::invalid_argument("rotation_basis: f must have positive degree");

    IMatrix B(n, std::vector<long long>(n, 0LL));

    Polynomial cur = v.reduce_mod(f);   // x^0 · v mod f

    for (int col = 0; col < n; ++col) {
        // Write cur into column `col`.
        for (int row = 0; row < n; ++row)
            B[row][col] = cur[row];

        if (col + 1 < n) {
            // Multiply by x: shift coefficients up by 1 degree, then reduce mod f.
            std::vector<Polynomial::Coeff> shifted(n + 1, 0LL);
            for (int i = 0; i <= cur.degree() && i < n; ++i)
                shifted[i + 1] = cur[i];
            cur = Polynomial(std::move(shifted)).reduce_mod(f);
        }
    }
    return B;
}

//  vec_mod_basis
std::vector<long long> vec_mod_basis(const std::vector<long long>& t,
                                    const IMatrix& B,
                                    const Matrix&  B_inv) {
    // Step 1: compute B^{-1} · t  (real arithmetic)
    std::vector<double> td(t.begin(), t.end());
    std::vector<double> Binv_t = linalg::matvec(B_inv, td);

    // Step 2: round to nearest integer vector
    std::vector<long long> rounded = linalg::round_vec(Binv_t);

    // Step 3: t mod B  =  t - B · round(B^{-1} · t)
    std::vector<long long> B_r = linalg::matvec(B, rounded);
    return linalg::sub(t, B_r);
}

//  compute_rDec  =  1 / (2 · ‖(B^sk_J)^{-1}‖_∞)       (Lemma 1)
double compute_rDec(const Matrix& B_sk_inv) {
    // B* = (B^{-1})^T  — dual basis vectors as rows of B_sk_inv transposed.
    // ‖B*‖ = max column norm of (B_sk_inv)^T = max row norm of B_sk_inv
    int n = (int)B_sk_inv.size();
    double max_col_norm = 0.0;

    // Column norms of B^* = row norms of B_sk_inv
    for (int j = 0; j < n; ++j) {
        double s = 0.0;
        for (int i = 0; i < n; ++i) s += B_sk_inv[i][j] * B_sk_inv[i][j];
        double norm = std::sqrt(s);
        if (norm > max_col_norm) max_col_norm = norm;
    }

    if (max_col_norm == 0.0) throw std::runtime_error("compute_rDec: degenerate basis");
    return 1.0 / (2.0 * max_col_norm);
}

//  Samplers
std::vector<long long> sample_gaussian(int n, double sigma, std::mt19937_64& rng) {
    std::normal_distribution<double> dist(0.0, sigma);
    std::vector<long long> v(n);
    
    for (int i = 0; i < n; ++i) {
        v[i] = (long long)std::round(dist(rng));
    }

    return v;
}

std::vector<long long> sample_uniform(int n, long long bound, std::mt19937_64& rng) {
    std::uniform_int_distribution<long long> dist(-bound, bound);
    std::vector<long long> v(n);
    for (int i = 0; i < n; ++i) v[i] = dist(rng);
    return v;
}
} // namespace vhsm::crypto::fhe