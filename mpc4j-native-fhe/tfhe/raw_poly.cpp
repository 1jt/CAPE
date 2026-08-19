#include "raw_poly.h"

#include <algorithm>
#include <numeric>
#include <stdexcept>

using namespace std;

namespace seal {
    namespace fusepirc {
        namespace {
            uint64_t add_uint_mod(uint64_t a, uint64_t b, uint64_t modulus) {
                return static_cast<uint64_t>((static_cast<__uint128_t>(a) + b) % modulus);
            }

            uint64_t sub_uint_mod(uint64_t a, uint64_t b, uint64_t modulus) {
                return a >= b ? a - b : static_cast<uint64_t>(static_cast<__uint128_t>(a) + modulus - b);
            }

            uint64_t mul_uint_mod(uint64_t a, uint64_t b, uint64_t modulus) {
                return static_cast<uint64_t>((static_cast<__uint128_t>(a) * b) % modulus);
            }

            uint64_t neg_uint_mod(uint64_t value, uint64_t modulus) {
                value %= modulus;
                return value == 0 ? 0 : modulus - value;
            }

            uint64_t normalize_mod_i64(int64_t value, uint64_t modulus) {
                int64_t reduced = value % static_cast<int64_t>(modulus);
                if (reduced < 0) {
                    reduced += static_cast<int64_t>(modulus);
                }
                return static_cast<uint64_t>(reduced);
            }

            void add_coeff(TorusPoly &out, uint32_t index, uint64_t value) {
                out.coeffs[index] = add_uint_mod(out.coeffs[index], value, out.modulus);
            }
        }

        void validate_torus_poly(const TorusPoly &poly) {
            if (poly.degree == 0) {
                throw invalid_argument("TorusPoly degree must be positive");
            }
            if (poly.modulus <= 1) {
                throw invalid_argument("TorusPoly modulus must be greater than 1");
            }
            if (poly.coeffs.size() != poly.degree) {
                throw invalid_argument("TorusPoly coefficient size must equal degree");
            }
            for (uint64_t coeff : poly.coeffs) {
                if (coeff >= poly.modulus) {
                    throw invalid_argument("TorusPoly coefficient out of modulus range");
                }
            }
        }

        void validate_same_ring(const TorusPoly &poly_a, const TorusPoly &poly_b) {
            validate_torus_poly(poly_a);
            validate_torus_poly(poly_b);
            if (poly_a.degree != poly_b.degree || poly_a.modulus != poly_b.modulus) {
                throw invalid_argument("TorusPoly ring mismatch");
            }
        }

        TorusPoly zero_poly(uint32_t degree, uint64_t modulus) {
            if (degree == 0 || modulus <= 1) {
                throw invalid_argument("invalid zero TorusPoly ring");
            }
            return TorusPoly{degree, modulus, vector<uint64_t>(degree, 0)};
        }

        TorusPoly constant_poly(uint64_t value, uint32_t degree, uint64_t modulus) {
            TorusPoly poly = zero_poly(degree, modulus);
            poly.coeffs[0] = value % modulus;
            return poly;
        }

        TorusPoly add_mod(const TorusPoly &poly_a, const TorusPoly &poly_b) {
            validate_same_ring(poly_a, poly_b);
            TorusPoly out = zero_poly(poly_a.degree, poly_a.modulus);
            for (uint32_t i = 0; i < poly_a.degree; i++) {
                out.coeffs[i] = add_uint_mod(poly_a.coeffs[i], poly_b.coeffs[i], poly_a.modulus);
            }
            return out;
        }

        TorusPoly sub_mod(const TorusPoly &poly_a, const TorusPoly &poly_b) {
            validate_same_ring(poly_a, poly_b);
            TorusPoly out = zero_poly(poly_a.degree, poly_a.modulus);
            for (uint32_t i = 0; i < poly_a.degree; i++) {
                out.coeffs[i] = sub_uint_mod(poly_a.coeffs[i], poly_b.coeffs[i], poly_a.modulus);
            }
            return out;
        }

        TorusPoly neg_mod(const TorusPoly &poly) {
            validate_torus_poly(poly);
            TorusPoly out = zero_poly(poly.degree, poly.modulus);
            for (uint32_t i = 0; i < poly.degree; i++) {
                out.coeffs[i] = neg_uint_mod(poly.coeffs[i], poly.modulus);
            }
            return out;
        }

        TorusPoly scalar_mul_mod(const TorusPoly &poly, uint64_t scalar) {
            validate_torus_poly(poly);
            TorusPoly out = zero_poly(poly.degree, poly.modulus);
            for (uint32_t i = 0; i < poly.degree; i++) {
                out.coeffs[i] = mul_uint_mod(poly.coeffs[i], scalar, poly.modulus);
            }
            return out;
        }

        TorusPoly negacyclic_mul_monomial(const TorusPoly &poly, int64_t exponent) {
            validate_torus_poly(poly);
            TorusPoly out = zero_poly(poly.degree, poly.modulus);
            uint64_t two_degree = static_cast<uint64_t>(2) * poly.degree;
            uint64_t shift = normalize_mod_i64(exponent, two_degree);
            for (uint32_t i = 0; i < poly.degree; i++) {
                uint64_t mapped = (static_cast<uint64_t>(i) + shift) % two_degree;
                uint64_t value = poly.coeffs[i];
                if (mapped >= poly.degree) {
                    mapped -= poly.degree;
                    value = neg_uint_mod(value, poly.modulus);
                }
                add_coeff(out, static_cast<uint32_t>(mapped), value);
            }
            return out;
        }

        TorusPoly automorphism(const TorusPoly &poly, uint32_t k) {
            validate_torus_poly(poly);
            uint32_t two_degree = 2 * poly.degree;
            if (gcd(k, two_degree) != 1) {
                throw invalid_argument("automorphism exponent must be coprime with 2N");
            }
            TorusPoly out = zero_poly(poly.degree, poly.modulus);
            for (uint32_t i = 0; i < poly.degree; i++) {
                uint64_t mapped = (static_cast<uint64_t>(i) * k) % two_degree;
                uint64_t value = poly.coeffs[i];
                if (mapped >= poly.degree) {
                    mapped -= poly.degree;
                    value = neg_uint_mod(value, poly.modulus);
                }
                add_coeff(out, static_cast<uint32_t>(mapped), value);
            }
            return out;
        }
    }
}
