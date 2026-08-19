#include "raw_rgsw.h"

#include <stdexcept>

using namespace std;

namespace seal {
    namespace fusepirc {
        namespace {
            uint64_t mul_uint_mod(uint64_t a, uint64_t b, uint64_t modulus) {
                return static_cast<uint64_t>((static_cast<__uint128_t>(a) * b) % modulus);
            }

            TorusPoly secret_times_scalar(const RawRlweSecretKey &sk, uint64_t scalar) {
                return scalar_mul_mod(sk.s, scalar);
            }

            void append_body_first_components(
                RawRgswCipher &cipher, uint64_t bit, const RawRlweSecretKey &sk,
                const RawExternalProductParams &params, double sigma) {
                vector<uint64_t> values = gadget_values(params.gadgetParams);
                for (uint32_t j = 0; j < params.gadgetParams.length; j++) {
                    uint64_t gadget = values[j];
                    TorusPoly message = constant_poly(mul_uint_mod(gadget, bit, params.rlweParams.modulus),
                        params.rlweParams.degree, params.rlweParams.modulus);
                    cipher.components.push_back(raw_rlwe_encrypt_poly(message, sk, params.rlweParams, sigma));
                }
                for (uint32_t j = 0; j < params.gadgetParams.length; j++) {
                    uint64_t gadget = values[j];
                    TorusPoly message = secret_times_scalar(sk, mul_uint_mod(gadget, bit, params.rlweParams.modulus));
                    cipher.components.push_back(raw_rlwe_encrypt_poly(message, sk, params.rlweParams, sigma));
                }
            }
        }

        void validate_raw_external_product_params(const RawExternalProductParams &params) {
            validate_raw_rlwe_params(params.rlweParams);
            validate_gadget_params(params.gadgetParams);
            if (params.gadgetParams.modulus != params.rlweParams.modulus) {
                throw invalid_argument("raw external product gadget / RLWE modulus mismatch");
            }
            if (params.layout.gadgetLength != params.gadgetParams.length
                || params.layout.gadgetBase != params.gadgetParams.base) {
                throw invalid_argument("raw external product layout / gadget mismatch");
            }
            if (params.layout.componentOrder != ComponentOrder::BODY_FIRST) {
                throw invalid_argument("raw external product currently requires body-first RGSW layout");
            }
        }

        void validate_raw_rgsw_cipher(const RawRgswCipher &cipher, const RawExternalProductParams &params) {
            validate_raw_external_product_params(params);
            if (cipher.layout.componentOrder != params.layout.componentOrder
                || cipher.layout.gadgetLength != params.layout.gadgetLength
                || cipher.layout.gadgetBase != params.layout.gadgetBase) {
                throw invalid_argument("raw RGSW layout mismatch");
            }
            if (cipher.params.degree != params.rlweParams.degree || cipher.params.modulus != params.rlweParams.modulus) {
                throw invalid_argument("raw RGSW params mismatch");
            }
            if (cipher.components.size() != 2 * params.gadgetParams.length) {
                throw invalid_argument("raw RGSW component count mismatch");
            }
            for (const RawRlweCipher &component : cipher.components) {
                if (component.params.degree != params.rlweParams.degree
                    || component.params.modulus != params.rlweParams.modulus || component.isNttForm) {
                    throw invalid_argument("raw RGSW component params mismatch");
                }
            }
        }

        RawRgswCipher raw_rgsw_encrypt_bit(
            uint64_t bit, const RawRlweSecretKey &sk, const RawExternalProductParams &params, double sigma) {
            if (bit > 1) {
                throw invalid_argument("raw RGSW plaintext bit must be 0 or 1");
            }
            validate_raw_external_product_params(params);
            validate_torus_poly(sk.s);
            if (sk.s.degree != params.rlweParams.degree || sk.s.modulus != params.rlweParams.modulus) {
                throw invalid_argument("raw RGSW secret key ring mismatch");
            }
            RawRgswCipher cipher;
            cipher.layout = params.layout;
            cipher.params = params.rlweParams;
            cipher.components.reserve(2 * params.gadgetParams.length);
            append_body_first_components(cipher, bit, sk, params, sigma);
            validate_raw_rgsw_cipher(cipher, params);
            return cipher;
        }

        RawRgswCipher raw_rgsw_encrypt_zero(
            const RawRlweSecretKey &sk, const RawExternalProductParams &params, double sigma) {
            return raw_rgsw_encrypt_bit(0, sk, params, sigma);
        }

        RawRgswCipher raw_rgsw_encrypt_one(
            const RawRlweSecretKey &sk, const RawExternalProductParams &params, double sigma) {
            return raw_rgsw_encrypt_bit(1, sk, params, sigma);
        }
    }
}
