#pragma once

#include <cstdint>
#include <vector>

namespace seal {
    namespace fusepirc {
        struct TorusPoly {
            std::uint32_t degree;
            std::uint64_t modulus;
            std::vector<std::uint64_t> coeffs;
        };

        TorusPoly zero_poly(std::uint32_t degree, std::uint64_t modulus);

        TorusPoly constant_poly(std::uint64_t value, std::uint32_t degree, std::uint64_t modulus);

        TorusPoly add_mod(const TorusPoly &poly_a, const TorusPoly &poly_b);

        TorusPoly sub_mod(const TorusPoly &poly_a, const TorusPoly &poly_b);

        TorusPoly neg_mod(const TorusPoly &poly);

        TorusPoly scalar_mul_mod(const TorusPoly &poly, std::uint64_t scalar);

        TorusPoly negacyclic_mul_monomial(const TorusPoly &poly, std::int64_t exponent);

        TorusPoly automorphism(const TorusPoly &poly, std::uint32_t k);

        void validate_torus_poly(const TorusPoly &poly);

        void validate_same_ring(const TorusPoly &poly_a, const TorusPoly &poly_b);
    }
}
