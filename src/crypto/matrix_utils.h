#ifndef VHSM_CRYPTO_MATRIX_UTILS
#define VHSM_CRYPTO_MATRIX_UTILS
/**
 * matrix_utils.hpp (Research perspective)
 * ────────────────
 * Small n×n dense matrix utilities needed for basis operations.
 * Uses partial-pivoting LU decomposition.
 */

#include "gentry_ideal_lattice.h"

#include <cmath>
#include <stdexcept>

namespace vhsm::crypto::fhe
{
namespace linalg
{
/**
 * Invert an n×n real matrix using Gaussian elimination with partial pivoting.
 * Throws if the matrix is singular (within a small numerical tolerance).
 */
inline Matrix invert(const Matrix& A)
{
    int n = (int) A.size();
    // Augmented matrix [A | I]
    Matrix aug(n, std::vector<double>(2 * n, 0.0));
    for (int i = 0; i < n; ++i)
    {
        for (int j = 0; j < n; ++j)
        {
            aug[i][j] = A[i][j];
        }
        aug[i][n + i] = 1.0;
    }

    for (int col = 0; col < n; ++col)
    {
        // Partial pivot
        int pivot = col;
        for (int row = col + 1; row < n; ++row)
        {
            if (std::abs(aug[row][col]) > std::abs(aug[pivot][col]))
            {
                pivot = row;
            }
        }
        std::swap(aug[col], aug[pivot]);

        double diag = aug[col][col];
        if (std::abs(diag) < 1e-12)
        {
            throw std::runtime_error("matrix inversion: singular matrix");
        }

        for (int j = col; j < 2 * n; ++j)
        {
            aug[col][j] /= diag;
        }

        for (int row = 0; row < n; ++row)
        {
            if (row == col)
            {
                continue;
            }
            double factor = aug[row][col];
            for (int j = col; j < 2 * n; ++j)
            {
                aug[row][j] -= factor * aug[col][j];
            }
        }
    }

    Matrix inv(n, std::vector<double>(n, 0.0));
    for (int i = 0; i < n; ++i)
    {
        for (int j = 0; j < n; ++j)
        {
            inv[i][j] = aug[i][n + j];
        }
    }
    return inv;
}

/// Convert integer matrix to double matrix.
inline Matrix to_double(const IMatrix& M)
{
    int n = (int) M.size();
    Matrix D(n, std::vector<double>(n));
    for (int i = 0; i < n; ++i)
    {
        for (int j = 0; j < n; ++j)
        {
            D[i][j] = (double) M[i][j];
        }
    }
    return D;
}

/// Invert an integer matrix (returned as double).
inline Matrix invert_imatrix(const IMatrix& M) { return invert(to_double(M)); }

/// Compute determinant via LU (for size tracking: det(I) = [R:I]).
inline double determinant(const Matrix& A)
{
    int n = (int) A.size();
    Matrix aug = A;
    double det = 1.0;
    for (int col = 0; col < n; ++col)
    {
        int pivot = col;
        for (int row = col + 1; row < n; ++row)
        {
            if (std::abs(aug[row][col]) > std::abs(aug[pivot][col]))
            {
                pivot = row;
            }
        }
        if (pivot != col)
        {
            std::swap(aug[col], aug[pivot]);
            det = -det;
        }
        if (std::abs(aug[col][col]) < 1e-12)
        {
            return 0.0;
        }
        det *= aug[col][col];
        for (int row = col + 1; row < n; ++row)
        {
            double factor = aug[row][col] / aug[col][col];
            for (int j = col; j < n; ++j)
            {
                aug[row][j] -= factor * aug[col][j];
            }
        }
    }
    return det;
}

inline double determinant(const IMatrix& M) { return determinant(to_double(M)); }

} // namespace linalg
} // namespace vhsm::crypto::fhe
#endif