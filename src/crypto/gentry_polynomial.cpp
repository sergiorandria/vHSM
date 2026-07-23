#include "gentry_polynomial.h"

#include <algorithm>
#include <cmath>
#include <sstream>

namespace vhsm::crypto::fhe
{

// reduce_mod
Polynomial Polynomial::reduce_mod(const Polynomial& f) const
{
    if (f.is_zero())
    {
        throw std::invalid_argument("reduce_mod: modulus is zero");
    }
    
    int fn = f.degree();
    if (fn <= 0)
    {
        throw std::invalid_argument("reduce_mod: modulus must have degree >= 1");
    }

    // Leading coefficient of f must be 1 (monic).
    if (f[fn] != 1)
    {
        throw std::invalid_argument("reduce_mod: modulus must be monic");
    }

    std::vector<Coeff> rem(coeffs_); // working copy

    // Standard polynomial long division, highest degree first.
    for (int i = (int) rem.size() - 1; i >= fn; --i)
    {
        if (rem[i] == 0)
        {
            continue;
        }
        Coeff lead = rem[i]; // coefficient to eliminate
        // subtract lead * x^(i-fn) * f(x)
        for (int j = 0; j <= fn; ++j)
        {
            rem[i - fn + j] -= lead * f[j];
        }
    }

    // Trim to degree < fn.
    rem.resize(fn);
    return Polynomial(std::move(rem));
}

// coeff_mod
Polynomial Polynomial::coeff_mod(Coeff q) const
{
    std::vector<Coeff> res(size());
    for (std::size_t i = 0; i < size(); ++i)
    {
        Coeff r = coeffs_[i] % q;
        // Centered representative in (-q/2, q/2]
        if (r > q / 2)
        {
            r -= q;
        }
        if (r <= -q / 2)
        {
            r += q;
        }
        res[i] = r;
    }
    return Polynomial(std::move(res));
}

// norms
double Polynomial::l2_norm() const
{
    double s = 0.0;
    for (auto c : coeffs_)
    {
        s += (double) c * (double) c;
    }
    return std::sqrt(s);
}

Polynomial::Coeff Polynomial::linf_norm() const
{
    Coeff m = 0;
    for (auto c : coeffs_)
    {
        Coeff a = c < 0 ? -c : c;
        if (a > m)
        {
            m = a;
        }
    }
    return m;
}

// output
std::ostream& operator<<(std::ostream& os, const Polynomial& p)
{
    if (p.is_zero())
    {
        os << "0";
        return os;
    }
    bool first = true;
    for (int i = p.degree(); i >= 0; --i)
    {
        if (p[i] == 0)
        {
            continue;
        }
        if (!first)
        {
            os << (p[i] > 0 ? " + " : " - ");
        }
        else if (p[i] < 0)
        {
            os << "-";
        }
        Polynomial::Coeff a = p[i] < 0 ? -p[i] : p[i];
        if (i == 0 || a != 1)
        {
            os << a;
        }
        if (i >= 1)
        {
            os << "x";
            if (i >= 2)
            {
                os << "^" << i;
            }
        }
        first = false;
    }
    return os;
}
} // namespace vhsm::crypto::fhe