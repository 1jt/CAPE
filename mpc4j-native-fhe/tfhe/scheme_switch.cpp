#include "scheme_switch.h"
#include "raw_ntt.h"

#include <atomic>
#include <iostream>
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

            RawExternalProductParams to_raw_ep_params(const SchemeSwitchParams &params) {
                return RawExternalProductParams{params.outputParams, params.gadgetParams, params.rgswLayout};
            }

            void validate_scheme_switch_key(const SchemeSwitchKey &key, const SchemeSwitchParams &params) {
                validate_scheme_switch_params(params);
                if (key.params.degree != params.outputParams.degree || key.params.modulus != params.outputParams.modulus) {
                    throw invalid_argument("SchemeSwitch key params mismatch");
                }
                if (key.gadgetParams.length != params.gadgetParams.length
                    || key.gadgetParams.base != params.gadgetParams.base
                    || key.gadgetParams.modulus != params.gadgetParams.modulus) {
                    throw invalid_argument("SchemeSwitch key gadget mismatch");
                }
                if (key.rgswLayout.componentOrder != params.rgswLayout.componentOrder
                    || key.rgswLayout.gadgetLength != params.rgswLayout.gadgetLength
                    || key.rgswLayout.gadgetBase != params.rgswLayout.gadgetBase) {
                    throw invalid_argument("SchemeSwitch key layout mismatch");
                }
                if (key.encryptedSkSquare.params.degree != params.outputParams.degree
                    || key.encryptedSkSquare.params.modulus != params.outputParams.modulus
                    || key.encryptedSkSquare.isNttForm) {
                    throw invalid_argument("SchemeSwitch encrypted sk^2 params mismatch");
                }
            }
        }

        void validate_scheme_switch_params(const SchemeSwitchParams &params) {
            validate_raw_rlwe_params(params.inputParams);
            validate_raw_rlwe_params(params.outputParams);
            validate_gadget_params(params.gadgetParams);
            if (params.inputParams.degree != params.outputParams.degree
                || params.inputParams.modulus != params.outputParams.modulus) {
                throw invalid_argument("SchemeSwitch input/output params must match in stage 7");
            }
            if (params.gadgetParams.modulus != params.outputParams.modulus) {
                throw invalid_argument("SchemeSwitch gadget modulus mismatch");
            }
            if (params.gadgetLength != params.gadgetParams.length || params.gadgetBase != params.gadgetParams.base) {
                throw invalid_argument("SchemeSwitch gadget metadata mismatch");
            }
            if (params.degree != params.outputParams.degree || params.modulus != params.outputParams.modulus) {
                throw invalid_argument("SchemeSwitch ring metadata mismatch");
            }
            if (!params.outputBodyFirst || params.rgswLayout.componentOrder != ComponentOrder::BODY_FIRST) {
                throw invalid_argument("SchemeSwitch stage 7 requires body-first output layout");
            }
            if (params.rgswLayout.gadgetLength != params.gadgetLength
                || params.rgswLayout.gadgetBase != params.gadgetBase) {
                throw invalid_argument("SchemeSwitch RGSW layout metadata mismatch");
            }
        }

        void validate_raw_rgsw_layout_for_external_product(
            const RawRgswCipher &rgsw, const RgswLayout &layout) {
            validate_raw_rlwe_params(rgsw.params);
            if (layout.gadgetLength == 0 || layout.gadgetBase <= 1
                || layout.componentOrder != ComponentOrder::BODY_FIRST) {
                throw invalid_argument("invalid raw RGSW layout for external product");
            }
            if (rgsw.layout.componentOrder != layout.componentOrder
                || rgsw.layout.gadgetLength != layout.gadgetLength
                || rgsw.layout.gadgetBase != layout.gadgetBase) {
                throw invalid_argument("raw RGSW layout mismatch for external product");
            }
            if (rgsw.components.size() != 2 * layout.gadgetLength) {
                throw invalid_argument("raw RGSW component count mismatch for external product");
            }
            for (const RawRlweCipher &component : rgsw.components) {
                if (component.params.degree != rgsw.params.degree
                    || component.params.modulus != rgsw.params.modulus || component.isNttForm) {
                    throw invalid_argument("raw RGSW component params mismatch for external product");
                }
            }
        }

        SchemeSwitchKey generate_scheme_switch_key(
            const RawRlweSecretKey &rlwe_sk, const SchemeSwitchParams &params, double sigma) {
            validate_scheme_switch_params(params);
            validate_torus_poly(rlwe_sk.s);
            if (rlwe_sk.s.degree != params.outputParams.degree || rlwe_sk.s.modulus != params.outputParams.modulus) {
                throw invalid_argument("SchemeSwitch secret key ring mismatch");
            }
            TorusPoly sk_square = negacyclic_mul_poly_auto(rlwe_sk.s, rlwe_sk.s);
            RawRlweCipher encrypted_sk_square = raw_rlwe_encrypt_poly(sk_square, rlwe_sk, params.outputParams, sigma);
            return SchemeSwitchKey{params.outputParams, params.gadgetParams, params.rgswLayout, encrypted_sk_square, {}};
        }

        RawRlweCipher scheme_switch_digit_to_secret_part(
            const RawRlweCipher &msg_digit, const SchemeSwitchKey &key, const SchemeSwitchParams &params) {
            validate_scheme_switch_key(key, params);
            if (msg_digit.params.degree != params.inputParams.degree || msg_digit.params.modulus != params.inputParams.modulus
                || msg_digit.isNttForm) {
                throw invalid_argument("SchemeSwitch msg digit params mismatch");
            }
            RawRlweCipher b_times_s{
                neg_mod(msg_digit.b),
                zero_poly(params.degree, params.modulus),
                params.outputParams,
                false,
                msg_digit.level
            };
            RawRlweCipher a_times_s_square = raw_rlwe_mul_plain_poly(key.encryptedSkSquare, msg_digit.a);
            // phase(msg_digit) = b - a*s = m.
            // phase((-b,0)) = b*s.
            // phase(a * Enc(s^2)) ~= a*s^2.
            // Therefore phase((-b,0) - a*Enc(s^2)) ~= b*s - a*s^2 = (b - a*s)*s = m*s.
            return raw_rlwe_sub(b_times_s, a_times_s_square);
        }

        RawRgswCipher scheme_switch_to_raw_rgsw(
            const vector<RawRlweCipher> &traced_digits, const SchemeSwitchKey &key,
            const SchemeSwitchParams &params) {
            validate_scheme_switch_key(key, params);
            if (traced_digits.size() != params.gadgetLength) {
                throw invalid_argument("SchemeSwitch traced digit count mismatch");
            }
            RawRgswCipher rgsw;
            rgsw.layout = params.rgswLayout;
            rgsw.params = params.outputParams;
            rgsw.components.resize(2 * params.gadgetLength);
            for (uint32_t j = 0; j < params.gadgetLength; j++) {
                if (traced_digits[j].params.degree != params.inputParams.degree
                    || traced_digits[j].params.modulus != params.inputParams.modulus
                    || traced_digits[j].isNttForm) {
                    throw invalid_argument("SchemeSwitch traced digit params mismatch");
                }
                RawRlweCipher body_component = traced_digits[j];
                RawRlweCipher secret_component = scheme_switch_digit_to_secret_part(traced_digits[j], key, params);
                rgsw.components[j] = body_component;
                rgsw.components[j + params.gadgetLength] = secret_component;
            }
            validate_raw_rgsw_cipher(rgsw, to_raw_ep_params(params));
            validate_raw_rgsw_layout_for_external_product(rgsw, params.rgswLayout);
            return rgsw;
        }
    }
}
