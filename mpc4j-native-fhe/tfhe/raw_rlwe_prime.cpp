#include "raw_rlwe_prime.h"

#include "gadget.h"

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

            RawRlweCipher raw_rlwe_mul_plain_poly_local(const RawRlweCipher &ct, const TorusPoly &plain) {
                validate_same_ring(ct.a, plain);
                if (ct.isNttForm) {
                    throw invalid_argument("RawRLWE' plaintext multiplication requires coefficient form");
                }
                return RawRlweCipher{
                    negacyclic_mul_poly(ct.a, plain),
                    negacyclic_mul_poly(ct.b, plain),
                    ct.params,
                    false,
                    ct.level
                };
            }

            void validate_same_prime_params(const RawRlwePrimeCipher &a, const RawRlwePrimeCipher &b) {
                validate_raw_rlwe_prime_cipher(a);
                validate_raw_rlwe_prime_cipher(b);
                if (a.params.degree != b.params.degree || a.params.modulus != b.params.modulus
                    || a.gadgetParams.length != b.gadgetParams.length
                    || a.gadgetParams.base != b.gadgetParams.base
                    || a.gadgetParams.modulus != b.gadgetParams.modulus) {
                    throw invalid_argument("RawRLWE' params mismatch");
                }
            }
        }

        void validate_raw_rlwe_prime_cipher(const RawRlwePrimeCipher &ct) {
            validate_raw_rlwe_params(ct.params);
            validate_gadget_params(ct.gadgetParams);
            if (ct.gadgetParams.modulus != ct.params.modulus) {
                throw invalid_argument("RawRLWE' gadget modulus mismatch");
            }
            if (ct.digits.size() != ct.gadgetParams.length) {
                throw invalid_argument("RawRLWE' digit count mismatch");
            }
            for (const RawRlweCipher &digit : ct.digits) {
                if (digit.params.degree != ct.params.degree || digit.params.modulus != ct.params.modulus
                    || digit.isNttForm) {
                    throw invalid_argument("RawRLWE' digit params mismatch");
                }
            }
        }

        RawRlwePrimeCipher raw_rlwe_prime_zero(
            const RawRlweParams &rlwe_params, const GadgetParams &gadget_params) {
            validate_raw_rlwe_params(rlwe_params);
            validate_gadget_params(gadget_params);
            if (gadget_params.modulus != rlwe_params.modulus) {
                throw invalid_argument("RawRLWE' zero gadget modulus mismatch");
            }
            RawRlwePrimeCipher out{{}, rlwe_params, gadget_params};
            out.digits.reserve(gadget_params.length);
            for (uint32_t j = 0; j < gadget_params.length; j++) {
                out.digits.push_back(RawRlweCipher{
                    zero_poly(rlwe_params.degree, rlwe_params.modulus),
                    zero_poly(rlwe_params.degree, rlwe_params.modulus),
                    rlwe_params,
                    false,
                    0
                });
            }
            return out;
        }

        RawRlwePrimeCipher trivial_raw_rlwe_prime_constant(
            uint64_t value, const RawRlweParams &rlwe_params, const GadgetParams &gadget_params) {
            validate_raw_rlwe_params(rlwe_params);
            validate_gadget_params(gadget_params);
            if (gadget_params.modulus != rlwe_params.modulus) {
                throw invalid_argument("RawRLWE' trivial gadget modulus mismatch");
            }
            RawRlwePrimeCipher out{{}, rlwe_params, gadget_params};
            out.digits.reserve(gadget_params.length);
            std::vector<uint64_t> values = gadget_values(gadget_params);
            for (uint32_t j = 0; j < gadget_params.length; j++) {
                uint64_t encoded = mul_uint_mod(values[j], value % rlwe_params.modulus, rlwe_params.modulus);
                out.digits.push_back(RawRlweCipher{
                    zero_poly(rlwe_params.degree, rlwe_params.modulus),
                    constant_poly(encoded, rlwe_params.degree, rlwe_params.modulus),
                    rlwe_params,
                    false,
                    0
                });
            }
            validate_raw_rlwe_prime_cipher(out);
            return out;
        }

        RawRlwePrimeCipher raw_rlwe_prime_add(
            const RawRlwePrimeCipher &a, const RawRlwePrimeCipher &b) {
            validate_same_prime_params(a, b);
            RawRlwePrimeCipher out{{}, a.params, a.gadgetParams};
            out.digits.reserve(a.digits.size());
            for (size_t i = 0; i < a.digits.size(); i++) {
                out.digits.push_back(raw_rlwe_add(a.digits[i], b.digits[i]));
            }
            return out;
        }

        RawRlwePrimeCipher raw_rlwe_prime_sub(
            const RawRlwePrimeCipher &a, const RawRlwePrimeCipher &b) {
            validate_same_prime_params(a, b);
            RawRlwePrimeCipher out{{}, a.params, a.gadgetParams};
            out.digits.reserve(a.digits.size());
            for (size_t i = 0; i < a.digits.size(); i++) {
                out.digits.push_back(raw_rlwe_sub(a.digits[i], b.digits[i]));
            }
            return out;
        }

        RawRlwePrimeCipher raw_rlwe_prime_mul_plain_poly(
            const RawRlwePrimeCipher &ct, const TorusPoly &plain) {
            validate_raw_rlwe_prime_cipher(ct);
            validate_torus_poly(plain);
            if (plain.degree != ct.params.degree || plain.modulus != ct.params.modulus) {
                throw invalid_argument("RawRLWE' plaintext multiplier ring mismatch");
            }
            RawRlwePrimeCipher out{{}, ct.params, ct.gadgetParams};
            out.digits.reserve(ct.digits.size());
            for (const RawRlweCipher &digit : ct.digits) {
                out.digits.push_back(raw_rlwe_mul_plain_poly_local(digit, plain));
            }
            return out;
        }

        RawRlwePrimeCipher raw_rgsw_mul_rlwe_prime(
            const RawRgswCipher &rgsw_bit, const RawRlwePrimeCipher &node,
            const RawExternalProductParams &ep_params, const RgswLayout &rgsw_layout) {
            validate_raw_rlwe_prime_cipher(node);
            validate_raw_external_product_params(ep_params);
            validate_raw_rgsw_cipher(rgsw_bit, ep_params);
            if (rgsw_bit.layout.gadgetLength != rgsw_layout.gadgetLength
                || rgsw_bit.layout.gadgetBase != rgsw_layout.gadgetBase
                || rgsw_bit.layout.componentOrder != rgsw_layout.componentOrder) {
                throw invalid_argument("RawRGSW x RawRLWE' layout mismatch");
            }
            if (ep_params.rlweParams.degree != node.params.degree
                || ep_params.rlweParams.modulus != node.params.modulus
                || ep_params.gadgetParams.length != node.gadgetParams.length
                || ep_params.gadgetParams.base != node.gadgetParams.base) {
                throw invalid_argument("RawRGSW x RawRLWE' params mismatch");
            }
            RawRlwePrimeCipher out{{}, node.params, node.gadgetParams};
            out.digits.reserve(node.digits.size());
            for (const RawRlweCipher &digit : node.digits) {
                out.digits.push_back(raw_external_product(digit, rgsw_bit, ep_params));
            }
            return out;
        }
    }
}
