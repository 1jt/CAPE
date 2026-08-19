#include "hom_trace.h"

#include <numeric>
#include <stdexcept>

using namespace std;

namespace seal {
    namespace fusepirc {
        namespace {
            bool is_power_of_two(uint32_t value) {
                return value != 0 && (value & (value - 1)) == 0;
            }

            uint32_t log2_exact(uint32_t value) {
                uint32_t log = 0;
                while ((UINT32_C(1) << log) < value) {
                    log++;
                }
                return log;
            }

            void validate_hom_trace_params(const HomTraceParams &params) {
                validate_raw_rlwe_params(params.params);
                validate_gadget_params(params.gadgetParams);
                if (!params.inputAlreadyTraceInverseScaled) {
                    throw invalid_argument("HomTrace input must already be trace-inverse scaled by stage 5");
                }
                if (params.degree != params.params.degree || params.modulus != params.params.modulus) {
                    throw invalid_argument("HomTrace params ring mismatch");
                }
                if (!is_power_of_two(params.degree)) {
                    throw invalid_argument("HomTrace degree must be a power of two");
                }
                uint32_t log_n = log2_exact(params.degree);
                if (params.automorphismExponents.size() != log_n) {
                    throw invalid_argument("HomTrace automorphism exponent count mismatch");
                }
                uint32_t two_degree = 2 * params.degree;
                for (uint32_t exponent : params.automorphismExponents) {
                    if (gcd(exponent, two_degree) != 1) {
                        throw invalid_argument("HomTrace automorphism exponent must be coprime with 2N");
                    }
                }
            }

            void validate_hom_trace_key(const HomTraceKey &key, const HomTraceParams &params) {
                validate_hom_trace_params(params);
                if (key.params.degree != params.params.degree || key.params.modulus != params.params.modulus) {
                    throw invalid_argument("HomTrace key params mismatch");
                }
                if (key.gadgetParams.modulus != params.gadgetParams.modulus) {
                    throw invalid_argument("HomTrace key gadget modulus mismatch");
                }
                if (key.automorphismKeys.size() != params.automorphismExponents.size()) {
                    throw invalid_argument("HomTrace key count mismatch");
                }
                for (size_t i = 0; i < key.automorphismKeys.size(); i++) {
                    if (key.automorphismKeys[i].automorphismExponent != params.automorphismExponents[i]) {
                        throw invalid_argument("HomTrace automorphism key exponent mismatch");
                    }
                }
            }
        }

        HomTraceParams make_hom_trace_params(const RawRlweParams &rlwe_params, const GadgetParams &gadget_params) {
            validate_raw_rlwe_params(rlwe_params);
            validate_gadget_params(gadget_params);
            if (!is_power_of_two(rlwe_params.degree)) {
                throw invalid_argument("HomTrace degree must be a power of two");
            }
            uint32_t log_n = log2_exact(rlwe_params.degree);
            vector<uint32_t> exponents;
            exponents.reserve(log_n);
            uint32_t two_degree = 2 * rlwe_params.degree;
            for (uint32_t i = log_n; i >= 1; i--) {
                uint32_t exponent = (UINT32_C(1) << i) + 1;
                if (gcd(exponent, two_degree) != 1) {
                    throw invalid_argument("generated HomTrace exponent is not coprime with 2N");
                }
                exponents.push_back(exponent);
            }
            HomTraceParams params{rlwe_params, gadget_params, rlwe_params.degree, rlwe_params.modulus, exponents, true};
            validate_hom_trace_params(params);
            return params;
        }

        HomTraceKey generate_hom_trace_key(
            const RawRlweSecretKey &sk, const HomTraceParams &params, double sigma) {
            validate_hom_trace_params(params);
            // HomTrace automorphism key switching must keep an exact reconstruction gadget:
            // using the torus-scaled RGSW gadget here injects approximation error directly into
            // the trace correction phase. The public RGSW/CMUX gadget remains params.gadgetParams.
            GadgetParams key_switch_gadget_params = params.gadgetParams;
            if (params.gadgetParams.scaleMode == GadgetParams::ScaleMode::TORUS_APPROX_HIGH) {
                key_switch_gadget_params = GadgetParams{
                    UINT64_C(65536),
                    16,
                    4,
                    params.gadgetParams.modulus,
                    true,
                    GadgetParams::ScaleMode::LOW_BITS_EXACT
                };
            } else {
                key_switch_gadget_params.scaleMode = GadgetParams::ScaleMode::LOW_BITS_EXACT;
            }
            validate_gadget_params(key_switch_gadget_params);
            HomTraceKey key{params.params, key_switch_gadget_params, {}};
            key.automorphismKeys.reserve(params.automorphismExponents.size());
            for (uint32_t exponent : params.automorphismExponents) {
                key.automorphismKeys.push_back(generate_raw_automorphism_key(sk, exponent, params.params,
                    key_switch_gadget_params, sigma));
            }
            validate_hom_trace_key(key, params);
            return key;
        }

        RawRlweCipher hom_trace(const RawRlweCipher &input, const HomTraceKey &key, const HomTraceParams &params) {
            validate_hom_trace_key(key, params);
            if (input.params.degree != params.degree || input.params.modulus != params.modulus || input.isNttForm) {
                throw invalid_argument("HomTrace input params mismatch");
            }
            RawRlweCipher ct = input;
            for (size_t i = 0; i < params.automorphismExponents.size(); i++) {
                uint32_t exponent = params.automorphismExponents[i];
                RawRlweCipher ct_auto = apply_raw_rlwe_automorphism(ct, exponent);
                RawRlweCipher ct_auto_switched = raw_automorphism_key_switch(ct_auto, key.automorphismKeys[i]);
                ct = raw_rlwe_add(ct, ct_auto_switched);
            }
            return ct;
        }

        vector<RawRlweCipher> hom_trace_many(
            const vector<RawRlweCipher> &inputs, const HomTraceKey &key, const HomTraceParams &params) {
            validate_hom_trace_key(key, params);
            vector<RawRlweCipher> outputs;
            outputs.reserve(inputs.size());
            for (const RawRlweCipher &input : inputs) {
                outputs.push_back(hom_trace(input, key, params));
            }
            return outputs;
        }
    }
}
