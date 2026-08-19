#include "circuit_bootstrap.h"

#include <chrono>
#include <future>
#include <iostream>
#include <numeric>
#include <stdexcept>
#include <string>
#include <utility>

using namespace std;

namespace seal {
    namespace fusepirc {
        namespace {
            constexpr bool FUSE_PIR_C_CB_PERF_LOG = false;
            using Clock = chrono::steady_clock;

            uint64_t elapsed_ms(const Clock::time_point &start) {
                return static_cast<uint64_t>(chrono::duration_cast<chrono::milliseconds>(
                    Clock::now() - start).count());
            }

            void cb_perf_log(const string &message) {
                if (FUSE_PIR_C_CB_PERF_LOG) {
                    cerr << "[FUSE_PIR_C-PERF] " << message << endl;
                }
            }

            bool is_power_of_two(uint32_t value) {
                return value != 0 && (value & (value - 1)) == 0;
            }

            uint64_t add_uint_mod(uint64_t a, uint64_t b, uint64_t modulus) {
                return static_cast<uint64_t>((static_cast<__uint128_t>(a) + b) % modulus);
            }

            uint64_t inv_two_mod(uint64_t modulus) {
                if ((modulus & 1U) == 0) {
                    throw invalid_argument("half-bias requires odd modulus");
                }
                return (modulus + 1) / 2;
            }

            GadgetParams exact_internal_gadget_for(const GadgetParams &output_gadget) {
                if (output_gadget.scaleMode == GadgetParams::ScaleMode::TORUS_APPROX_HIGH) {
                    return GadgetParams{
                        UINT64_C(65536),
                        16,
                        4,
                        output_gadget.modulus,
                        true,
                        GadgetParams::ScaleMode::LOW_BITS_EXACT
                    };
                }
                GadgetParams exact = output_gadget;
                exact.scaleMode = GadgetParams::ScaleMode::LOW_BITS_EXACT;
                return exact;
            }

            void apply_trace_affine_bias(
                vector<RawRlweCipher> &traced_digits, const vector<uint64_t> &output_values, uint64_t modulus) {
                if (traced_digits.size() != output_values.size()) {
                    throw invalid_argument("trace affine bias digit count mismatch");
                }
                uint64_t inv_two = inv_two_mod(modulus);
                for (size_t j = 0; j < traced_digits.size(); j++) {
                    uint64_t half_output = mul_mod_uint64(output_values[j], inv_two, modulus);
                    traced_digits[j].b.coeffs[0] = add_uint_mod(traced_digits[j].b.coeffs[0], half_output, modulus);
                }
            }

            void validate_circuit_bootstrap_params(const CircuitBootstrapParams &params) {
                if (params.lweParams.delta != params.lweParams.q / 2) {
                    throw invalid_argument("CircuitBootstrap LWE params must use delta = q / 2");
                }
                validate_raw_rlwe_params(params.rlweParams);
                validate_gadget_params(params.outputGadgetParams);
                validate_raw_external_product_params(params.outputExternalProductParams);
                validate_gadget_params(params.mvFbsCmuxGadgetParams);
                validate_raw_external_product_params(params.mvFbsExternalProductParams);
                validate_gadget_params(params.homTraceKeySwitchGadgetParams);
                validate_gadget_params(params.schemeSwitchKeySwitchGadgetParams);
                validate_mv_fbs_params(params.mvFbsParams);
                validate_scheme_switch_params(params.schemeSwitchParams);
                if (!is_power_of_two(params.rlweParams.degree)) {
                    throw invalid_argument("CircuitBootstrap raw RLWE degree must be a power of two");
                }
                if (std::gcd(static_cast<uint64_t>(params.rlweParams.degree), params.rlweParams.modulus) != 1) {
                    throw invalid_argument("CircuitBootstrap requires gcd(N,Q)=1 for trace-inverse scaling");
                }
                if ((params.rlweParams.modulus & 1U) == 0) {
                    throw invalid_argument("CircuitBootstrap raw RLWE modulus must be odd");
                }
                if (params.gadgetLength != params.outputGadgetParams.length
                    || params.gadgetBase != params.outputGadgetParams.base) {
                    throw invalid_argument("CircuitBootstrap gadget metadata mismatch");
                }
                if (params.outputRgswLayout.gadgetLength != params.gadgetLength
                    || params.outputRgswLayout.gadgetBase != params.gadgetBase
                    || params.outputRgswLayout.componentOrder != ComponentOrder::BODY_FIRST
                    || params.rgswLayout.gadgetLength != params.gadgetLength
                    || params.rgswLayout.gadgetBase != params.gadgetBase
                    || params.rgswLayout.componentOrder != ComponentOrder::BODY_FIRST) {
                    throw invalid_argument("CircuitBootstrap RGSW layout mismatch");
                }
                if (params.mvFbsCmuxRgswLayout.gadgetLength != params.mvFbsCmuxGadgetParams.length
                    || params.mvFbsCmuxRgswLayout.gadgetBase != params.mvFbsCmuxGadgetParams.base
                    || params.mvFbsCmuxRgswLayout.componentOrder != ComponentOrder::BODY_FIRST) {
                    throw invalid_argument("CircuitBootstrap MV-FBS CMUX layout mismatch");
                }
                if (params.degree != params.rlweParams.degree || params.modulus != params.rlweParams.modulus) {
                    throw invalid_argument("CircuitBootstrap ring metadata mismatch");
                }
                if (params.mvFbsParams.rlweParams.degree != params.degree
                    || params.homTraceParams.params.degree != params.degree
                    || params.schemeSwitchParams.outputParams.degree != params.degree
                    || params.outputExternalProductParams.rlweParams.degree != params.degree
                    || params.mvFbsExternalProductParams.rlweParams.degree != params.degree
                    || params.externalProductParams.rlweParams.degree != params.degree) {
                    throw invalid_argument("CircuitBootstrap degree mismatch across stages");
                }
                if (params.mvFbsParams.rlweParams.modulus != params.modulus
                    || params.homTraceParams.params.modulus != params.modulus
                    || params.schemeSwitchParams.outputParams.modulus != params.modulus
                    || params.outputExternalProductParams.rlweParams.modulus != params.modulus
                    || params.mvFbsExternalProductParams.rlweParams.modulus != params.modulus
                    || params.externalProductParams.rlweParams.modulus != params.modulus) {
                    throw invalid_argument("CircuitBootstrap modulus mismatch across stages");
                }
                if (params.mvFbsParams.gadgetParams.length != params.outputGadgetParams.length
                    || params.schemeSwitchParams.gadgetParams.length != params.outputGadgetParams.length
                    || params.outputExternalProductParams.gadgetParams.length != params.outputGadgetParams.length
                    || params.externalProductParams.gadgetParams.length != params.outputGadgetParams.length) {
                    throw invalid_argument("CircuitBootstrap output gadget length mismatch across stages");
                }
                if (params.mvFbsExternalProductParams.gadgetParams.length != params.mvFbsCmuxGadgetParams.length
                    || params.homTraceParams.gadgetParams.length != params.homTraceKeySwitchGadgetParams.length) {
                    throw invalid_argument("CircuitBootstrap internal gadget length mismatch across stages");
                }
                if (!params.homTraceParams.inputAlreadyTraceInverseScaled) {
                    throw invalid_argument("CircuitBootstrap requires MV-FBS trace-inverse scaled inputs to HomTrace");
                }
            }

            void validate_evaluation_key(
                const CircuitBootstrapEvaluationKey &evaluation_key, const CircuitBootstrapParams &params) {
                if (evaluation_key.mvFbsKey.bootstrappingKey.size() != params.lweParams.n) {
                    throw invalid_argument("CircuitBootstrap MV-FBS key dimension mismatch");
                }
                if (evaluation_key.homTraceKey.automorphismKeys.size()
                    != params.homTraceParams.automorphismExponents.size()) {
                    throw invalid_argument("CircuitBootstrap HomTrace key size mismatch");
                }
                if (evaluation_key.schemeSwitchKey.params.degree != params.degree
                    || evaluation_key.schemeSwitchKey.params.modulus != params.modulus) {
                    throw invalid_argument("CircuitBootstrap SchemeSwitch key params mismatch");
                }
            }

            void validate_cached_evaluation_key(
                const CachedCircuitBootstrapEvaluationKey &evaluation_key, const CircuitBootstrapParams &params) {
                validate_evaluation_key(evaluation_key.coeffKey, params);
                if (evaluation_key.mvFbsBootstrappingKeyNtt.size() != params.lweParams.n) {
                    throw invalid_argument("cached CircuitBootstrap MV-FBS key dimension mismatch");
                }
            }
        }

        CircuitBootstrapParams make_circuit_bootstrap_params(
            const LweParams &lwe_params, const RawRlweParams &rlwe_params,
            const GadgetParams &gadget_params, const RgswLayout &rgsw_layout) {
            if (lwe_params.delta != lwe_params.q / 2) {
                throw invalid_argument("CircuitBootstrap LWE params must use delta = q / 2");
            }
            if (!is_power_of_two(rlwe_params.degree)) {
                throw invalid_argument("CircuitBootstrap raw RLWE degree must be a power of two");
            }
            if (std::gcd(static_cast<uint64_t>(rlwe_params.degree), rlwe_params.modulus) != 1) {
                throw invalid_argument("CircuitBootstrap requires gcd(N,Q)=1 for trace-inverse scaling");
            }
            if ((rlwe_params.modulus & 1U) == 0) {
                throw invalid_argument("CircuitBootstrap raw RLWE modulus must be odd");
            }
            if (gadget_params.length != rgsw_layout.gadgetLength
                || gadget_params.base != rgsw_layout.gadgetBase
                || gadget_params.modulus != rlwe_params.modulus) {
                throw invalid_argument("CircuitBootstrap gadget / RGSW layout mismatch");
            }
            if (rgsw_layout.componentOrder != ComponentOrder::BODY_FIRST) {
                throw invalid_argument("CircuitBootstrap requires the stage 3/5/7 body-first RGSW layout");
            }
            GadgetParams mv_fbs_cmux_gadget = exact_internal_gadget_for(gadget_params);
            RgswLayout mv_fbs_cmux_layout{
                mv_fbs_cmux_gadget.length,
                mv_fbs_cmux_gadget.base,
                ComponentOrder::BODY_FIRST
            };
            RawExternalProductParams output_ep_params{rlwe_params, gadget_params, rgsw_layout};
            RawExternalProductParams mv_fbs_ep_params{rlwe_params, mv_fbs_cmux_gadget, mv_fbs_cmux_layout};
            GadgetParams hom_trace_key_switch_gadget = exact_internal_gadget_for(gadget_params);
            GadgetParams scheme_switch_key_switch_gadget = exact_internal_gadget_for(gadget_params);
            MvFbsParams mv_fbs_params{
                lwe_params,
                rlwe_params,
                gadget_params,
                gadget_params.length,
                rlwe_params.degree,
                rlwe_params.modulus,
                lwe_params.q,
                2,
                static_cast<uint32_t>(2 * rlwe_params.degree),
                true
            };
            if (gadget_params.scaleMode == GadgetParams::ScaleMode::TORUS_APPROX_HIGH) {
                mv_fbs_params.lweParams.sigma = 0.001;
            }
            HomTraceParams hom_trace_params = make_hom_trace_params(rlwe_params, hom_trace_key_switch_gadget);
            SchemeSwitchParams scheme_switch_params{
                rlwe_params,
                rlwe_params,
                gadget_params,
                rgsw_layout,
                gadget_params.length,
                gadget_params.base,
                rlwe_params.modulus,
                rlwe_params.degree,
                true
            };
            CircuitBootstrapParams params{
                lwe_params,
                rlwe_params,
                gadget_params,
                rgsw_layout,
                output_ep_params,
                mv_fbs_cmux_gadget,
                mv_fbs_cmux_layout,
                mv_fbs_ep_params,
                hom_trace_key_switch_gadget,
                scheme_switch_key_switch_gadget,
                gadget_params,
                rgsw_layout,
                output_ep_params,
                mv_fbs_params,
                hom_trace_params,
                scheme_switch_params,
                gadget_params.length,
                gadget_params.base,
                rlwe_params.degree,
                rlwe_params.modulus
            };
            validate_circuit_bootstrap_params(params);
            return params;
        }

        pair<CircuitBootstrapClientSecretState, CircuitBootstrapEvaluationKey> generate_circuit_bootstrap_keys(
            const CircuitBootstrapParams &params, double sigma) {
            validate_circuit_bootstrap_params(params);
            LweSecretKey lwe_sk = binary_lwe_keygen(params.lweParams);
            RawRlweSecretKey rlwe_sk = raw_rlwe_keygen(params.rlweParams);
            MvFbsKey mv_fbs_key = generate_mv_fbs_key(
                lwe_sk, rlwe_sk, params.mvFbsParams, params.mvFbsExternalProductParams
            );
            double key_switch_sigma = params.gadgetParams.scaleMode == GadgetParams::ScaleMode::TORUS_APPROX_HIGH
                ? 0.001 : sigma;
            HomTraceKey hom_trace_key = generate_hom_trace_key(rlwe_sk, params.homTraceParams, key_switch_sigma);
            SchemeSwitchKey scheme_switch_key = generate_scheme_switch_key(
                rlwe_sk, params.schemeSwitchParams, key_switch_sigma
            );
            CircuitBootstrapClientSecretState client_state{lwe_sk, rlwe_sk};
            CircuitBootstrapEvaluationKey evaluation_key{mv_fbs_key, hom_trace_key, scheme_switch_key};
            validate_evaluation_key(evaluation_key, params);
            return {client_state, evaluation_key};
        }

        vector<uint64_t> build_rgsw_gadget_output_values(
            const GadgetParams &gadget_params, uint64_t modulus_q) {
            validate_gadget_params(gadget_params);
            if (gadget_params.modulus != modulus_q) {
                throw invalid_argument("CircuitBootstrap gadget output modulus mismatch");
            }
            return gadget_values(gadget_params);
        }

        CachedCircuitBootstrapEvaluationKey make_cached_circuit_bootstrap_key(
            CircuitBootstrapEvaluationKey key, const CircuitBootstrapParams &params) {
            validate_circuit_bootstrap_params(params);
            validate_evaluation_key(key, params);
            RawNttParams ntt_params = get_cached_raw_ntt_params(params.degree, params.modulus);
            CachedCircuitBootstrapEvaluationKey cached;
            cached.mvFbsBootstrappingKeyNtt.reserve(key.mvFbsKey.bootstrappingKey.size());
            for (const RawRgswCipher &rgsw : key.mvFbsKey.bootstrappingKey) {
                cached.mvFbsBootstrappingKeyNtt.push_back(make_cached_raw_rgsw_ntt(rgsw, ntt_params));
            }
            cached.coeffKey = std::move(key);
            validate_cached_evaluation_key(cached, params);
            return cached;
        }

        void prepare_workspace(CircuitBootstrapWorkspace &workspace, const CircuitBootstrapParams &params) {
            if (workspace.degree == params.degree && workspace.modulus == params.modulus
                && workspace.gadgetLength == params.gadgetLength && workspace.gadgetBase == params.gadgetBase
                && workspace.testPolySet.testPolys.size() == params.gadgetLength) {
                workspace.mvFbsOutputs.clear();
                workspace.tracedDigits.clear();
                return;
            }
            workspace.degree = params.degree;
            workspace.modulus = params.modulus;
            workspace.gadgetLength = params.gadgetLength;
            workspace.gadgetBase = params.gadgetBase;
            workspace.outputValues = build_rgsw_gadget_output_values(params.gadgetParams, params.modulus);
            workspace.testPolySet = build_mv_fbs_test_polynomial_set(workspace.outputValues, params.mvFbsParams);
            workspace.mvFbsOutputs.clear();
            workspace.tracedDigits.clear();
            workspace.mvFbsOutputs.reserve(params.gadgetLength);
            workspace.tracedDigits.reserve(params.gadgetLength);
        }

        RawRgswCipher secure_lwe_to_rgsw_with_workspace(
            const LweCipher &lwe_bit, const CircuitBootstrapEvaluationKey &evaluation_key,
            const CircuitBootstrapParams &params, CircuitBootstrapWorkspace &workspace,
            CircuitBootstrapTiming *timing) {
            auto total_start = Clock::now();
            validate_circuit_bootstrap_params(params);
            validate_evaluation_key(evaluation_key, params);
            if (lwe_bit.a.size() != params.lweParams.n) {
                throw invalid_argument("CircuitBootstrap LWE dimension mismatch");
            }
            prepare_workspace(workspace, params);
            auto step_start = Clock::now();
            workspace.mvFbsOutputs = mv_fbs_no_sample_extract(
                lwe_bit, evaluation_key.mvFbsKey, workspace.testPolySet, params.mvFbsParams,
                params.mvFbsExternalProductParams
            );
            uint64_t mv_fbs_ms = elapsed_ms(step_start);
            step_start = Clock::now();
            workspace.tracedDigits = hom_trace_many(
                workspace.mvFbsOutputs, evaluation_key.homTraceKey, params.homTraceParams
            );
            apply_trace_affine_bias(workspace.tracedDigits, workspace.outputValues, params.modulus);
            uint64_t hom_trace_ms = elapsed_ms(step_start);
            step_start = Clock::now();
            RawRgswCipher rgsw = scheme_switch_to_raw_rgsw(
                workspace.tracedDigits, evaluation_key.schemeSwitchKey, params.schemeSwitchParams
            );
            validate_raw_rgsw_layout_for_external_product(rgsw, params.rgswLayout);
            uint64_t scheme_switch_ms = elapsed_ms(step_start);
            uint64_t total_ms = elapsed_ms(total_start);
            if (timing != nullptr) {
                timing->mvFbsMs = mv_fbs_ms;
                timing->homTraceMs = hom_trace_ms;
                timing->schemeSwitchMs = scheme_switch_ms;
                timing->totalMs = total_ms;
            }
            cb_perf_log("secure_lwe_to_rgsw.mv_fbs_ms=" + to_string(mv_fbs_ms)
                + ", hom_trace_ms=" + to_string(hom_trace_ms)
                + ", scheme_switch_ms=" + to_string(scheme_switch_ms)
                + ", total_ms=" + to_string(total_ms));
            return rgsw;
        }

        RawRgswCipher secure_lwe_to_rgsw_with_workspace_cached_ntt(
            const LweCipher &lwe_bit, const CachedCircuitBootstrapEvaluationKey &evaluation_key,
            const CircuitBootstrapParams &params, CircuitBootstrapWorkspace &workspace,
            CircuitBootstrapTiming *timing) {
            auto total_start = Clock::now();
            validate_circuit_bootstrap_params(params);
            validate_cached_evaluation_key(evaluation_key, params);
            if (lwe_bit.a.size() != params.lweParams.n) {
                throw invalid_argument("cached CircuitBootstrap LWE dimension mismatch");
            }
            prepare_workspace(workspace, params);
            auto step_start = Clock::now();
            workspace.mvFbsOutputs = mv_fbs_no_sample_extract_cached_ntt(
                lwe_bit, evaluation_key.mvFbsBootstrappingKeyNtt, workspace.testPolySet, params.mvFbsParams,
                params.mvFbsExternalProductParams, workspace.nttWorkspace
            );
            uint64_t mv_fbs_ms = elapsed_ms(step_start);
            step_start = Clock::now();
            workspace.tracedDigits = hom_trace_many(
                workspace.mvFbsOutputs, evaluation_key.coeffKey.homTraceKey, params.homTraceParams
            );
            apply_trace_affine_bias(workspace.tracedDigits, workspace.outputValues, params.modulus);
            uint64_t hom_trace_ms = elapsed_ms(step_start);
            step_start = Clock::now();
            RawRgswCipher rgsw = scheme_switch_to_raw_rgsw(
                workspace.tracedDigits, evaluation_key.coeffKey.schemeSwitchKey, params.schemeSwitchParams
            );
            validate_raw_rgsw_layout_for_external_product(rgsw, params.rgswLayout);
            uint64_t scheme_switch_ms = elapsed_ms(step_start);
            uint64_t total_ms = elapsed_ms(total_start);
            if (timing != nullptr) {
                timing->mvFbsMs = mv_fbs_ms;
                timing->homTraceMs = hom_trace_ms;
                timing->schemeSwitchMs = scheme_switch_ms;
                timing->totalMs = total_ms;
            }
            cb_perf_log("secure_lwe_to_rgsw.cached_ntt.mv_fbs_ms=" + to_string(mv_fbs_ms)
                + ", hom_trace_ms=" + to_string(hom_trace_ms)
                + ", scheme_switch_ms=" + to_string(scheme_switch_ms)
                + ", total_ms=" + to_string(total_ms));
            return rgsw;
        }

        RawRgswCipher secure_lwe_to_rgsw(
            const LweCipher &lwe_bit, const CircuitBootstrapEvaluationKey &evaluation_key,
            const CircuitBootstrapParams &params) {
            CircuitBootstrapWorkspace workspace;
            return secure_lwe_to_rgsw_with_workspace(lwe_bit, evaluation_key, params, workspace, nullptr);
        }

        vector<RawRgswCipher> secure_lwe_bits_to_rgsw_batch(
            const vector<LweCipher> &lwe_bits, const CircuitBootstrapEvaluationKey &evaluation_key,
            const CircuitBootstrapParams &params, const char *log_prefix) {
            validate_circuit_bootstrap_params(params);
            validate_evaluation_key(evaluation_key, params);
            vector<RawRgswCipher> out;
            out.reserve(lwe_bits.size());
            CircuitBootstrapWorkspace workspace;
            uint64_t total_mv_fbs_ms = 0;
            uint64_t total_hom_trace_ms = 0;
            uint64_t total_scheme_switch_ms = 0;
            uint64_t total_ms = 0;
            if (log_prefix != nullptr) {
                cb_perf_log(string("generateReply.") + log_prefix
                    + "_secure_lwe_to_rgsw_begin, bitCount=" + to_string(lwe_bits.size()));
            }
            for (size_t bit_index = 0; bit_index < lwe_bits.size(); bit_index++) {
                if (log_prefix != nullptr) {
                    cb_perf_log(string("secure_lwe_to_rgsw.") + log_prefix + ".bit"
                        + to_string(bit_index) + ".begin");
                }
                CircuitBootstrapTiming timing;
                out.push_back(secure_lwe_to_rgsw_with_workspace(
                    lwe_bits[bit_index], evaluation_key, params, workspace, &timing
                ));
                total_mv_fbs_ms += timing.mvFbsMs;
                total_hom_trace_ms += timing.homTraceMs;
                total_scheme_switch_ms += timing.schemeSwitchMs;
                total_ms += timing.totalMs;
                if (log_prefix != nullptr) {
                    cb_perf_log(string("secure_lwe_to_rgsw.") + log_prefix + ".bit"
                        + to_string(bit_index) + ".mv_fbs_ms=" + to_string(timing.mvFbsMs)
                        + ", hom_trace_ms=" + to_string(timing.homTraceMs)
                        + ", scheme_switch_ms=" + to_string(timing.schemeSwitchMs)
                        + ", total_ms=" + to_string(timing.totalMs));
                }
            }
            if (log_prefix != nullptr) {
                uint64_t avg_ms = lwe_bits.empty() ? 0 : total_ms / lwe_bits.size();
                cb_perf_log(string("generateReply.") + log_prefix
                    + "_secure_lwe_to_rgsw_summary_ms=" + to_string(total_ms)
                    + ", convertedBitCount=" + to_string(lwe_bits.size())
                    + ", avgBitMs=" + to_string(avg_ms)
                    + ", mv_fbs_total_ms=" + to_string(total_mv_fbs_ms)
                    + ", hom_trace_total_ms=" + to_string(total_hom_trace_ms)
                    + ", scheme_switch_total_ms=" + to_string(total_scheme_switch_ms));
            }
            return out;
        }

        vector<RawRgswCipher> secure_lwe_bits_to_rgsw_batch_cached_ntt(
            const vector<LweCipher> &lwe_bits, const CachedCircuitBootstrapEvaluationKey &evaluation_key,
            const CircuitBootstrapParams &params, const char *log_prefix) {
            validate_circuit_bootstrap_params(params);
            validate_cached_evaluation_key(evaluation_key, params);
            vector<RawRgswCipher> out(lwe_bits.size());
            vector<CircuitBootstrapTiming> timings(lwe_bits.size());
            uint64_t total_mv_fbs_ms = 0;
            uint64_t total_hom_trace_ms = 0;
            uint64_t total_scheme_switch_ms = 0;
            uint64_t total_ms = 0;
            auto batch_start = Clock::now();
            if (log_prefix != nullptr) {
                cb_perf_log(string("generateReply.") + log_prefix
                    + "_secure_lwe_to_rgsw_cached_ntt_begin, bitCount=" + to_string(lwe_bits.size()));
            }
            if (lwe_bits.size() <= 1) {
                CircuitBootstrapWorkspace workspace;
                for (size_t bit_index = 0; bit_index < lwe_bits.size(); bit_index++) {
                    if (log_prefix != nullptr) {
                        cb_perf_log(string("secure_lwe_to_rgsw.cached_ntt.") + log_prefix + ".bit"
                            + to_string(bit_index) + ".begin");
                    }
                    out[bit_index] = secure_lwe_to_rgsw_with_workspace_cached_ntt(
                        lwe_bits[bit_index], evaluation_key, params, workspace, &timings[bit_index]
                    );
                }
            } else {
                vector<future<void>> futures;
                futures.reserve(lwe_bits.size());
                for (size_t bit_index = 0; bit_index < lwe_bits.size(); bit_index++) {
                    if (log_prefix != nullptr) {
                        cb_perf_log(string("secure_lwe_to_rgsw.cached_ntt.") + log_prefix + ".bit"
                            + to_string(bit_index) + ".begin");
                    }
                    futures.push_back(async(launch::async, [&, bit_index]() {
                        CircuitBootstrapWorkspace workspace;
                        out[bit_index] = secure_lwe_to_rgsw_with_workspace_cached_ntt(
                            lwe_bits[bit_index], evaluation_key, params, workspace, &timings[bit_index]
                        );
                    }));
                }
                for (future<void> &future : futures) {
                    future.get();
                }
            }
            for (size_t bit_index = 0; bit_index < lwe_bits.size(); bit_index++) {
                const CircuitBootstrapTiming &timing = timings[bit_index];
                total_mv_fbs_ms += timing.mvFbsMs;
                total_hom_trace_ms += timing.homTraceMs;
                total_scheme_switch_ms += timing.schemeSwitchMs;
                total_ms += timing.totalMs;
                if (log_prefix != nullptr) {
                    cb_perf_log(string("secure_lwe_to_rgsw.cached_ntt.") + log_prefix + ".bit"
                        + to_string(bit_index) + ".mv_fbs_ms=" + to_string(timing.mvFbsMs)
                        + ", hom_trace_ms=" + to_string(timing.homTraceMs)
                        + ", scheme_switch_ms=" + to_string(timing.schemeSwitchMs)
                        + ", total_ms=" + to_string(timing.totalMs));
                }
            }
            if (log_prefix != nullptr) {
                uint64_t avg_ms = lwe_bits.empty() ? 0 : total_ms / lwe_bits.size();
                cb_perf_log(string("generateReply.") + log_prefix
                    + "_secure_lwe_to_rgsw_cached_ntt_summary_ms=" + to_string(total_ms)
                    + ", convertedBitCount=" + to_string(lwe_bits.size())
                    + ", avgBitMs=" + to_string(avg_ms)
                    + ", wallMs=" + to_string(elapsed_ms(batch_start))
                    + ", mv_fbs_total_ms=" + to_string(total_mv_fbs_ms)
                    + ", hom_trace_total_ms=" + to_string(total_hom_trace_ms)
                    + ", scheme_switch_total_ms=" + to_string(total_scheme_switch_ms));
            }
            return out;
        }

        vector<RawRgswCipher> secure_lwe_bits_to_rgsw(
            const vector<LweCipher> &lwe_bits, const CircuitBootstrapEvaluationKey &evaluation_key,
            const CircuitBootstrapParams &params) {
            return secure_lwe_bits_to_rgsw_batch(lwe_bits, evaluation_key, params, nullptr);
        }
    }
}
