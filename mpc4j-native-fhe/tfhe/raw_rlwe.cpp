#include "raw_rlwe.h"
#include "raw_ntt.h"

#include <atomic>
#include <cmath>
#include <iostream>
#include <random>
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

            uint64_t add_signed_mod(uint64_t a, int64_t e, uint64_t modulus) {
                if (e >= 0) {
                    return add_uint_mod(a, static_cast<uint64_t>(e), modulus);
                }
                uint64_t magnitude = static_cast<uint64_t>(-e);
                return sub_uint_mod(a, magnitude % modulus, modulus);
            }

            TorusPoly negacyclic_mul_poly(const TorusPoly &poly_a, const TorusPoly &poly_b) {
                validate_same_ring(poly_a, poly_b);
                TorusPoly out = zero_poly(poly_a.degree, poly_a.modulus);
                uint64_t two_degree = static_cast<uint64_t>(2) * poly_a.degree;
                for (uint32_t i = 0; i < poly_a.degree; i++) {
                    for (uint32_t j = 0; j < poly_b.degree; j++) {
                        uint64_t mapped = (static_cast<uint64_t>(i) + j) % two_degree;
                        uint64_t product = mul_uint_mod(poly_a.coeffs[i], poly_b.coeffs[j], poly_a.modulus);
                        if (mapped >= poly_a.degree) {
                            mapped -= poly_a.degree;
                            product = product == 0 ? 0 : poly_a.modulus - product;
                        }
                        out.coeffs[static_cast<uint32_t>(mapped)] = add_uint_mod(
                            out.coeffs[static_cast<uint32_t>(mapped)], product, poly_a.modulus
                        );
                    }
                }
                return out;
            }

            TorusPoly negacyclic_mul_poly_auto(const TorusPoly &poly_a, const TorusPoly &poly_b) {
                validate_same_ring(poly_a, poly_b);
                if (can_use_raw_ntt(poly_a.degree, poly_a.modulus)) {
                    return negacyclic_ntt_mul(
                        poly_a, poly_b, get_cached_raw_ntt_params(poly_a.degree, poly_a.modulus));
                }
                return negacyclic_mul_poly(poly_a, poly_b);
            }

            int64_t sample_centered_error(mt19937_64 &rng, double sigma) {
                normal_distribution<double> distribution(0.0, sigma);
                return static_cast<int64_t>(llround(distribution(rng)));
            }

            TorusPoly sample_uniform_poly(const RawRlweParams &params) {
                random_device rd;
                mt19937_64 rng((static_cast<uint64_t>(rd()) << 32) ^ rd());
                TorusPoly poly = zero_poly(params.degree, params.modulus);
                for (uint64_t &coeff : poly.coeffs) {
                    coeff = rng() % params.modulus;
                }
                return poly;
            }

            TorusPoly sample_error_poly(const RawRlweParams &params, double sigma) {
                if (sigma <= 0) {
                    throw invalid_argument("raw RLWE sigma must be positive");
                }
                random_device rd;
                mt19937_64 rng((static_cast<uint64_t>(rd()) << 32) ^ rd());
                TorusPoly poly = zero_poly(params.degree, params.modulus);
                for (uint64_t &coeff : poly.coeffs) {
                    coeff = add_signed_mod(0, sample_centered_error(rng, sigma), params.modulus);
                }
                return poly;
            }

            void validate_cipher(const RawRlweCipher &ct) {
                validate_raw_rlwe_params(ct.params);
                validate_same_ring(ct.a, ct.b);
                if (ct.a.degree != ct.params.degree || ct.a.modulus != ct.params.modulus) {
                    throw invalid_argument("raw RLWE ciphertext ring mismatch");
                }
            }

            void validate_same_cipher_ring(const RawRlweCipher &ct_a, const RawRlweCipher &ct_b) {
                validate_cipher(ct_a);
                validate_cipher(ct_b);
                if (ct_a.params.degree != ct_b.params.degree || ct_a.params.modulus != ct_b.params.modulus) {
                    throw invalid_argument("raw RLWE ciphertext parameter mismatch");
                }
                if (ct_a.isNttForm || ct_b.isNttForm) {
                    throw invalid_argument("raw RLWE operations currently require coefficient form");
                }
            }
        }

        void validate_raw_rlwe_params(const RawRlweParams &params) {
            if (params.degree == 0) {
                throw invalid_argument("raw RLWE degree must be positive");
            }
            if (params.modulus <= 1) {
                throw invalid_argument("raw RLWE modulus must be greater than 1");
            }
            if (params.logModulus == 0 || params.logModulus > 63) {
                throw invalid_argument("raw RLWE log modulus must be in [1,63]");
            }
            if ((params.modulus >> (params.logModulus - 1)) == 0) {
                throw invalid_argument("raw RLWE log modulus inconsistent with modulus");
            }
            if (!params.useRns && !params.rnsPrimes.empty()) {
                throw invalid_argument("raw RLWE RNS primes set while useRns is false");
            }
        }

        RawRlweSecretKey raw_rlwe_keygen(const RawRlweParams &params) {
            validate_raw_rlwe_params(params);
            random_device rd;
            TorusPoly s = zero_poly(params.degree, params.modulus);
            for (uint64_t &coeff : s.coeffs) {
                coeff = rd() & 1U;
            }
            return RawRlweSecretKey{s};
        }

        RawRlweCipher raw_rlwe_encrypt_zero(const RawRlweSecretKey &sk, const RawRlweParams &params, double sigma) {
            return raw_rlwe_encrypt_poly(zero_poly(params.degree, params.modulus), sk, params, sigma);
        }

        RawRlweCipher raw_rlwe_encrypt_poly(
            const TorusPoly &message, const RawRlweSecretKey &sk, const RawRlweParams &params, double sigma) {
            validate_raw_rlwe_params(params);
            validate_same_ring(message, sk.s);
            if (message.degree != params.degree || message.modulus != params.modulus) {
                throw invalid_argument("raw RLWE message ring mismatch");
            }
            TorusPoly a = sample_uniform_poly(params);
            TorusPoly error = sample_error_poly(params, sigma);
            TorusPoly as = negacyclic_mul_poly_auto(a, sk.s);
            TorusPoly b = add_mod(add_mod(as, message), error);
            return RawRlweCipher{a, b, params, false, 0};
        }

        TorusPoly raw_rlwe_decrypt_phase(const RawRlweCipher &ct, const RawRlweSecretKey &sk) {
            validate_cipher(ct);
            validate_same_ring(ct.a, sk.s);
            if (ct.isNttForm) {
                throw invalid_argument("raw RLWE decrypt phase requires coefficient form");
            }
            return sub_mod(ct.b, negacyclic_mul_poly_auto(ct.a, sk.s));
        }

        RawRlweCipher raw_rlwe_add(const RawRlweCipher &ct_a, const RawRlweCipher &ct_b) {
            validate_same_cipher_ring(ct_a, ct_b);
            return RawRlweCipher{
                add_mod(ct_a.a, ct_b.a), add_mod(ct_a.b, ct_b.b), ct_a.params, false,
                max(ct_a.level, ct_b.level)
            };
        }

        RawRlweCipher raw_rlwe_sub(const RawRlweCipher &ct_a, const RawRlweCipher &ct_b) {
            validate_same_cipher_ring(ct_a, ct_b);
            return RawRlweCipher{
                sub_mod(ct_a.a, ct_b.a), sub_mod(ct_a.b, ct_b.b), ct_a.params, false,
                max(ct_a.level, ct_b.level)
            };
        }

        RawRlweCipher raw_rlwe_scalar_mul(const RawRlweCipher &ct, uint64_t scalar) {
            validate_cipher(ct);
            if (ct.isNttForm) {
                throw invalid_argument("raw RLWE scalar multiplication requires coefficient form");
            }
            return RawRlweCipher{
                scalar_mul_mod(ct.a, scalar), scalar_mul_mod(ct.b, scalar), ct.params, false, ct.level
            };
        }

        RawRlweCipher raw_rlwe_mul_monomial(const RawRlweCipher &ct, int64_t exponent) {
            validate_cipher(ct);
            if (ct.isNttForm) {
                throw invalid_argument("raw RLWE monomial multiplication requires coefficient form");
            }
            return RawRlweCipher{
                negacyclic_mul_monomial(ct.a, exponent), negacyclic_mul_monomial(ct.b, exponent), ct.params,
                false, ct.level
            };
        }

        RawRlweCipher raw_rlwe_automorphism(const RawRlweCipher &ct, uint32_t k) {
            validate_cipher(ct);
            if (ct.isNttForm) {
                throw invalid_argument("raw RLWE automorphism requires coefficient form");
            }
            return RawRlweCipher{
                automorphism(ct.a, k), automorphism(ct.b, k), ct.params, false, ct.level
            };
        }
    }
}
