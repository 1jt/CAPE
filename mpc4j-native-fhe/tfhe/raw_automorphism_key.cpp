#include "raw_automorphism_key.h"
#include "raw_ntt.h"

#include <atomic>
#include <iostream>
#include <numeric>
#include <stdexcept>

using namespace std;

namespace seal {
    namespace fusepirc {
        namespace {
            uint64_t add_uint_mod(uint64_t a, uint64_t b, uint64_t modulus) {
                return static_cast<uint64_t>((static_cast<__uint128_t>(a) + b) % modulus);
            }

            uint64_t mul_uint_mod(uint64_t a, uint64_t b, uint64_t modulus) {
                return static_cast<uint64_t>((static_cast<__uint128_t>(a) * b) % modulus);
            }

            uint64_t pow_base_mod(uint64_t base, uint32_t exponent, uint64_t modulus) {
                uint64_t result = 1 % modulus;
                for (uint32_t i = 0; i < exponent; i++) {
                    result = mul_uint_mod(result, base, modulus);
                }
                return result;
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

            RawRlweCipher raw_rlwe_mul_plain_poly(const RawRlweCipher &ct, const TorusPoly &plain) {
                validate_same_ring(ct.a, plain);
                return RawRlweCipher{
                    negacyclic_mul_poly_auto(ct.a, plain),
                    negacyclic_mul_poly_auto(ct.b, plain),
                    ct.params,
                    false,
                    ct.level
                };
            }

            void validate_aut_key(const RawAutomorphismKey &aut_key) {
                validate_raw_rlwe_params(aut_key.params);
                validate_gadget_params(aut_key.gadgetParams);
                if (aut_key.gadgetParams.modulus != aut_key.params.modulus) {
                    throw invalid_argument("raw automorphism key gadget / RLWE modulus mismatch");
                }
                uint32_t two_degree = 2 * aut_key.params.degree;
                if (gcd(aut_key.automorphismExponent, two_degree) != 1) {
                    throw invalid_argument("raw automorphism key exponent must be coprime with 2N");
                }
                if (aut_key.keySwitchComponents.size() != aut_key.gadgetParams.length) {
                    throw invalid_argument("raw automorphism key component count mismatch");
                }
                for (const RawRlweCipher &component : aut_key.keySwitchComponents) {
                    if (component.params.degree != aut_key.params.degree
                        || component.params.modulus != aut_key.params.modulus || component.isNttForm) {
                        throw invalid_argument("raw automorphism key component params mismatch");
                    }
                }
            }
        }

        RawRlweCipher apply_raw_rlwe_automorphism(const RawRlweCipher &ct, uint32_t k) {
            if (ct.isNttForm) {
                throw invalid_argument("raw RLWE automorphism requires coefficient form");
            }
            uint32_t two_degree = 2 * ct.params.degree;
            if (gcd(k, two_degree) != 1) {
                throw invalid_argument("raw RLWE automorphism exponent must be coprime with 2N");
            }
            return raw_rlwe_automorphism(ct, k);
        }

        RawAutomorphismKey generate_raw_automorphism_key(
            const RawRlweSecretKey &sk, uint32_t automorphism_exponent, const RawRlweParams &params,
            const GadgetParams &gadget_params, double sigma) {
            validate_raw_rlwe_params(params);
            validate_gadget_params(gadget_params);
            validate_torus_poly(sk.s);
            if (sk.s.degree != params.degree || sk.s.modulus != params.modulus) {
                throw invalid_argument("raw automorphism key secret key ring mismatch");
            }
            if (gadget_params.modulus != params.modulus) {
                throw invalid_argument("raw automorphism key gadget modulus mismatch");
            }
            TorusPoly old_secret = automorphism(sk.s, automorphism_exponent);
            RawAutomorphismKey aut_key{automorphism_exponent, params, gadget_params, {}};
            vector<uint64_t> values = gadget_values(gadget_params);
            aut_key.keySwitchComponents.reserve(gadget_params.length);
            for (uint32_t j = 0; j < gadget_params.length; j++) {
                TorusPoly message = scalar_mul_mod(old_secret, values[j]);
                aut_key.keySwitchComponents.push_back(raw_rlwe_encrypt_poly(message, sk, params, sigma));
            }
            validate_aut_key(aut_key);
            return aut_key;
        }

        RawRlweCipher raw_automorphism_key_switch(
            const RawRlweCipher &ct_under_auto_sk, const RawAutomorphismKey &aut_key) {
            validate_aut_key(aut_key);
            if (ct_under_auto_sk.params.degree != aut_key.params.degree
                || ct_under_auto_sk.params.modulus != aut_key.params.modulus || ct_under_auto_sk.isNttForm) {
                throw invalid_argument("raw automorphism key switch ciphertext params mismatch");
            }
            vector<TorusPoly> digits = gadget_decompose(ct_under_auto_sk.a, aut_key.gadgetParams);
            RawRlweCipher correction{
                zero_poly(aut_key.params.degree, aut_key.params.modulus),
                zero_poly(aut_key.params.degree, aut_key.params.modulus),
                aut_key.params,
                false,
                ct_under_auto_sk.level
            };
            for (size_t i = 0; i < digits.size(); i++) {
                correction = raw_rlwe_add(correction, raw_rlwe_mul_plain_poly(aut_key.keySwitchComponents[i],
                    digits[i]));
            }
            // Phase convention: phase = b - a*s.
            // correction.phase = correction.b - correction.a*s_new ~= a*s_old.
            // out = (-correction.a, b - correction.b), hence:
            // out.phase = b - correction.b - (-correction.a)*s_new
            //           = b - (correction.b - correction.a*s_new)
            //           ~= b - a*s_old.
            return RawRlweCipher{
                neg_mod(correction.a),
                sub_mod(ct_under_auto_sk.b, correction.b),
                aut_key.params,
                false,
                ct_under_auto_sk.level
            };
        }
    }
}
