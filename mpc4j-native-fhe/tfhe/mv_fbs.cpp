#include "mv_fbs.h"

#include <chrono>
#include <iostream>
#include <numeric>
#include <stdexcept>
#include <string>

using namespace std;

namespace seal {
    namespace fusepirc {
        namespace {
            constexpr bool FUSE_PIR_C_MV_FBS_PERF_LOG = false;
            using Clock = chrono::steady_clock;

            uint64_t elapsed_ms(const Clock::time_point &start) {
                return static_cast<uint64_t>(chrono::duration_cast<chrono::milliseconds>(
                    Clock::now() - start).count());
            }

            void mv_fbs_perf_log(const string &message) {
                if (FUSE_PIR_C_MV_FBS_PERF_LOG) {
                    cerr << "[FUSE_PIR_C-PERF] " << message << endl;
                }
            }

            int64_t round_mod_switch(uint64_t value, uint64_t from_modulus, uint32_t to_modulus) {
                __uint128_t numerator = static_cast<__uint128_t>(value) * to_modulus * 2 + from_modulus;
                __uint128_t denominator = static_cast<__uint128_t>(from_modulus) * 2;
                uint64_t rounded = static_cast<uint64_t>(numerator / denominator);
                return static_cast<int64_t>(rounded % to_modulus);
            }

            bool is_power_of_two(uint32_t value) {
                return value != 0 && (value & (value - 1)) == 0;
            }
        }

        uint64_t mul_mod_uint64(uint64_t a, uint64_t b, uint64_t modulus) {
            if (modulus <= 1) {
                throw invalid_argument("modulus must be greater than 1");
            }
            return static_cast<uint64_t>((static_cast<__uint128_t>(a % modulus) * (b % modulus)) % modulus);
        }

        uint64_t mod_inverse_uint64(uint64_t x, uint64_t modulus) {
            if (modulus <= 1) {
                throw invalid_argument("modulus must be greater than 1");
            }
            uint64_t normalized = x % modulus;
            if (normalized == 0 || std::gcd(normalized, modulus) != 1) {
                throw invalid_argument("modular inverse does not exist");
            }
            __int128 old_r = normalized;
            __int128 r = modulus;
            __int128 old_s = 1;
            __int128 s = 0;
            while (r != 0) {
                __int128 quotient = old_r / r;
                __int128 next_r = old_r - quotient * r;
                old_r = r;
                r = next_r;
                __int128 next_s = old_s - quotient * s;
                old_s = s;
                s = next_s;
            }
            if (old_r != 1) {
                throw invalid_argument("modular inverse does not exist");
            }
            __int128 result = old_s % static_cast<__int128>(modulus);
            if (result < 0) {
                result += modulus;
            }
            if (result == 0) {
                throw invalid_argument("invalid zero modular inverse");
            }
            return static_cast<uint64_t>(result);
        }

        uint64_t trace_inverse_scale_value(uint64_t output_value, uint32_t degree_n, uint64_t modulus_q) {
            if (!is_power_of_two(degree_n)) {
                throw invalid_argument("trace-inverse scaling requires power-of-two degree");
            }
            if (std::gcd(static_cast<uint64_t>(degree_n), modulus_q) != 1) {
                throw invalid_argument("trace-inverse scaling requires gcd(N,Q)=1");
            }
            uint64_t inv_n = mod_inverse_uint64(static_cast<uint64_t>(degree_n) % modulus_q, modulus_q);
            return mul_mod_uint64(output_value, inv_n, modulus_q);
        }

        void validate_mv_fbs_params(const MvFbsParams &params) {
            if (params.degree == 0 || params.modulus <= 1 || params.lweModulus <= 1) {
                throw invalid_argument("invalid MV-FBS modulus or degree");
            }
            if (params.plaintextModulus != 2) {
                throw invalid_argument("MV-FBS stage 5 only supports bit plaintext modulus p = 2");
            }
            if (params.rotationModulus != 2 * params.degree) {
                throw invalid_argument("MV-FBS rotation modulus must be 2N");
            }
            if (params.degree % 4 != 0) {
                throw invalid_argument("MV-FBS p=2 test polynomial requires N divisible by 4");
            }
            if (!is_power_of_two(params.degree)) {
                throw invalid_argument("MV-FBS degree must be a power of two");
            }
            if (params.scaleByTraceInverse && std::gcd(static_cast<uint64_t>(params.degree), params.modulus) != 1) {
                throw invalid_argument("MV-FBS trace-inverse scaling requires gcd(N,Q)=1");
            }
            if (params.rlweParams.degree != params.degree || params.rlweParams.modulus != params.modulus) {
                throw invalid_argument("MV-FBS raw RLWE params mismatch");
            }
            if (params.lweParams.q != params.lweModulus || params.lweParams.delta != params.lweModulus / 2) {
                throw invalid_argument("MV-FBS LWE params must use delta = q / 2");
            }
            if (params.outputDigitNum != params.gadgetParams.length) {
                throw invalid_argument("MV-FBS outputDigitNum must equal gadget length");
            }
            validate_raw_rlwe_params(params.rlweParams);
            validate_gadget_params(params.gadgetParams);
        }

        ModSwitchedLwe mod_switch_for_blind_rotation(const LweCipher &lwe, const MvFbsParams &params) {
            validate_mv_fbs_params(params);
            if (lwe.a.size() != params.lweParams.n) {
                throw invalid_argument("MV-FBS LWE dimension mismatch");
            }
            ModSwitchedLwe ms_lwe;
            ms_lwe.rotationModulus = params.rotationModulus;
            ms_lwe.aBar.reserve(lwe.a.size());
            for (uint64_t a_i : lwe.a) {
                ms_lwe.aBar.push_back(round_mod_switch(a_i % params.lweModulus, params.lweModulus,
                    params.rotationModulus));
            }
            ms_lwe.bBar = round_mod_switch(lwe.b % params.lweModulus, params.lweModulus, params.rotationModulus);
            return ms_lwe;
        }

        uint64_t encode_trace_inverse_scaled_value(uint64_t output_value, const MvFbsParams &params) {
            validate_mv_fbs_params(params);
            if (!params.scaleByTraceInverse) {
                return output_value % params.modulus;
            }
            return trace_inverse_scale_value(output_value, params.degree, params.modulus);
        }

        TorusPoly build_mv_fbs_bit_test_polynomial(uint64_t output_value, const MvFbsParams &params) {
            validate_mv_fbs_params(params);
            uint64_t scaled = params.scaleByTraceInverse
                ? mul_mod_uint64(output_value, mod_inverse_uint64(
                    (static_cast<uint64_t>(2) * params.degree) % params.modulus, params.modulus), params.modulus)
                : output_value % params.modulus;
            uint64_t negative_scaled = scaled == 0 ? 0 : params.modulus - scaled;
            TorusPoly test_poly = zero_poly(params.degree, params.modulus);
            uint32_t first_block_end = params.degree / 4;
            uint32_t middle_block_end = first_block_end + params.degree / 2;
            for (uint32_t i = 0; i < first_block_end; i++) {
                test_poly.coeffs[i] = negative_scaled;
            }
            for (uint32_t i = middle_block_end; i < params.degree; i++) {
                test_poly.coeffs[i] = scaled;
            }
            return test_poly;
        }

        MvFbsTestPolynomialSet build_mv_fbs_test_polynomial_set(
            const vector<uint64_t> &output_values, const MvFbsParams &params) {
            validate_mv_fbs_params(params);
            if (output_values.size() != params.outputDigitNum) {
                throw invalid_argument("MV-FBS output value size must equal outputDigitNum");
            }
            MvFbsTestPolynomialSet set;
            set.outputValues = output_values;
            set.testPolys.reserve(output_values.size());
            for (uint64_t output_value : output_values) {
                set.testPolys.push_back(build_mv_fbs_bit_test_polynomial(output_value, params));
            }
            return set;
        }

        RawRlweCipher init_mv_fbs_accumulator(
            const TorusPoly &test_poly, int64_t b_bar, const RawRlweParams &rlwe_params) {
            validate_raw_rlwe_params(rlwe_params);
            validate_torus_poly(test_poly);
            if (test_poly.degree != rlwe_params.degree || test_poly.modulus != rlwe_params.modulus) {
                throw invalid_argument("MV-FBS accumulator test polynomial ring mismatch");
            }
            TorusPoly rotated = negacyclic_mul_monomial(test_poly, b_bar);
            return RawRlweCipher{
                zero_poly(rlwe_params.degree, rlwe_params.modulus),
                rotated,
                rlwe_params,
                false,
                2
            };
        }

        RawRlweCipher cmux_blind_rotate_single_output(
            const RawRlweCipher &initial_acc, const ModSwitchedLwe &ms_lwe, const MvFbsKey &key,
            const MvFbsParams &params, const RawExternalProductParams &ep_params) {
            validate_mv_fbs_params(params);
            validate_raw_external_product_params(ep_params);
            if (key.bootstrappingKey.size() != params.lweParams.n || ms_lwe.aBar.size() != params.lweParams.n) {
                throw invalid_argument("MV-FBS bootstrapping key / mod-switched LWE dimension mismatch");
            }
            if (ms_lwe.rotationModulus != params.rotationModulus) {
                throw invalid_argument("MV-FBS rotation modulus mismatch");
            }
            // FUSE_PIR_C convention:
            // phase = b - <a,s>
            // rotation exponent = bBar - sum_i aBar_i * s_i.
            // Therefore the blind rotation applies -aBar_i when s_i = 1.
            RawRlweCipher acc = initial_acc;
            auto rotate_start = Clock::now();
            mv_fbs_perf_log("mv_fbs.blind_rotate_begin, lweN=" + to_string(ms_lwe.aBar.size())
                + ", rawRlweN=" + to_string(params.degree));
            for (size_t i = 0; i < ms_lwe.aBar.size(); i++) {
                RawRlweCipher shifted = raw_rlwe_mul_monomial(acc, -ms_lwe.aBar[i]);
                acc = raw_cmux(key.bootstrappingKey[i], shifted, acc, ep_params);
                size_t done = i + 1;
                if (done == 1 || done % 64 == 0 || done == ms_lwe.aBar.size()) {
                    mv_fbs_perf_log("mv_fbs.cmux_progress=" + to_string(done) + "/"
                        + to_string(ms_lwe.aBar.size()) + ", total_ms=" + to_string(elapsed_ms(rotate_start)));
                }
            }
            mv_fbs_perf_log("mv_fbs.blind_rotate_done_ms=" + to_string(elapsed_ms(rotate_start)));
            return acc;
        }

        RawRlweCipher cmux_blind_rotate_single_output_cached_ntt(
            const RawRlweCipher &initial_acc, const ModSwitchedLwe &ms_lwe,
            const vector<CachedRawRgswCipherNtt> &cached_bootstrapping_key, const MvFbsParams &params,
            const RawExternalProductParams &ep_params, RawNttWorkspace &workspace) {
            validate_mv_fbs_params(params);
            validate_raw_external_product_params(ep_params);
            if (cached_bootstrapping_key.size() != params.lweParams.n
                || ms_lwe.aBar.size() != params.lweParams.n) {
                throw invalid_argument("cached MV-FBS bootstrapping key / mod-switched LWE dimension mismatch");
            }
            if (ms_lwe.rotationModulus != params.rotationModulus) {
                throw invalid_argument("cached MV-FBS rotation modulus mismatch");
            }
            RawRlweCipher acc = initial_acc;
            auto rotate_start = Clock::now();
            mv_fbs_perf_log("mv_fbs.cached_ntt.blind_rotate_begin, lweN=" + to_string(ms_lwe.aBar.size())
                + ", rawRlweN=" + to_string(params.degree));
            for (size_t i = 0; i < ms_lwe.aBar.size(); i++) {
                RawRlweCipher shifted = raw_rlwe_mul_monomial(acc, -ms_lwe.aBar[i]);
                acc = raw_cmux_cached_ntt(cached_bootstrapping_key[i], shifted, acc, ep_params, workspace);
                size_t done = i + 1;
                if (done == 1 || done % 64 == 0 || done == ms_lwe.aBar.size()) {
                    mv_fbs_perf_log("mv_fbs.cached_ntt.cmux_progress=" + to_string(done) + "/"
                        + to_string(ms_lwe.aBar.size()) + ", total_ms=" + to_string(elapsed_ms(rotate_start)));
                }
            }
            mv_fbs_perf_log("mv_fbs.cached_ntt.blind_rotate_done_ms=" + to_string(elapsed_ms(rotate_start)));
            return acc;
        }

        vector<RawRlweCipher> mv_fbs_no_sample_extract(
            const LweCipher &lwe, const MvFbsKey &key, const MvFbsTestPolynomialSet &test_poly_set,
            const MvFbsParams &params, const RawExternalProductParams &ep_params) {
            validate_mv_fbs_params(params);
            validate_raw_external_product_params(ep_params);
            if (test_poly_set.testPolys.size() != params.outputDigitNum
                || test_poly_set.outputValues.size() != params.outputDigitNum) {
                throw invalid_argument("MV-FBS test polynomial set size mismatch");
            }
            ModSwitchedLwe ms_lwe = mod_switch_for_blind_rotation(lwe, params);
            vector<RawRlweCipher> outputs;
            outputs.reserve(test_poly_set.testPolys.size());
            auto mv_fbs_start = Clock::now();
            mv_fbs_perf_log("mv_fbs.begin, outputCount=" + to_string(test_poly_set.testPolys.size())
                + ", lweN=" + to_string(params.lweParams.n) + ", rawRlweN=" + to_string(params.degree));
            size_t digit_index = 0;
            for (const TorusPoly &test_poly : test_poly_set.testPolys) {
                auto digit_start = Clock::now();
                mv_fbs_perf_log("mv_fbs.output_digit_index=" + to_string(digit_index) + ".begin");
                RawRlweCipher acc0 = init_mv_fbs_accumulator(test_poly, ms_lwe.bBar, params.rlweParams);
                outputs.push_back(cmux_blind_rotate_single_output(acc0, ms_lwe, key, params, ep_params));
                mv_fbs_perf_log("mv_fbs.output_digit_index=" + to_string(digit_index)
                    + ".done_ms=" + to_string(elapsed_ms(digit_start)));
                digit_index++;
            }
            mv_fbs_perf_log("mv_fbs.done_ms=" + to_string(elapsed_ms(mv_fbs_start)));
            return outputs;
        }

        vector<RawRlweCipher> mv_fbs_no_sample_extract_cached_ntt(
            const LweCipher &lwe, const vector<CachedRawRgswCipherNtt> &cached_bootstrapping_key,
            const MvFbsTestPolynomialSet &test_poly_set, const MvFbsParams &params,
            const RawExternalProductParams &ep_params, RawNttWorkspace &workspace) {
            validate_mv_fbs_params(params);
            validate_raw_external_product_params(ep_params);
            if (test_poly_set.testPolys.size() != params.outputDigitNum
                || test_poly_set.outputValues.size() != params.outputDigitNum) {
                throw invalid_argument("cached MV-FBS test polynomial set size mismatch");
            }
            ModSwitchedLwe ms_lwe = mod_switch_for_blind_rotation(lwe, params);
            vector<RawRlweCipher> outputs;
            outputs.reserve(test_poly_set.testPolys.size());
            auto mv_fbs_start = Clock::now();
            mv_fbs_perf_log("mv_fbs.cached_ntt.begin, outputCount=" + to_string(test_poly_set.testPolys.size())
                + ", lweN=" + to_string(params.lweParams.n) + ", rawRlweN=" + to_string(params.degree));
            size_t digit_index = 0;
            for (const TorusPoly &test_poly : test_poly_set.testPolys) {
                auto digit_start = Clock::now();
                mv_fbs_perf_log("mv_fbs.cached_ntt.output_digit_index=" + to_string(digit_index) + ".begin");
                RawRlweCipher acc0 = init_mv_fbs_accumulator(test_poly, ms_lwe.bBar, params.rlweParams);
                outputs.push_back(cmux_blind_rotate_single_output_cached_ntt(
                    acc0, ms_lwe, cached_bootstrapping_key, params, ep_params, workspace
                ));
                mv_fbs_perf_log("mv_fbs.cached_ntt.output_digit_index=" + to_string(digit_index)
                    + ".done_ms=" + to_string(elapsed_ms(digit_start)));
                digit_index++;
            }
            mv_fbs_perf_log("mv_fbs.cached_ntt.done_ms=" + to_string(elapsed_ms(mv_fbs_start)));
            return outputs;
        }

        MvFbsKey generate_mv_fbs_key(
            const LweSecretKey &lwe_sk, const RawRlweSecretKey &rlwe_sk, const MvFbsParams &params,
            const RawExternalProductParams &ep_params) {
            validate_mv_fbs_params(params);
            validate_raw_external_product_params(ep_params);
            if (lwe_sk.s.size() != params.lweParams.n) {
                throw invalid_argument("MV-FBS LWE secret key dimension mismatch");
            }
            if (ep_params.layout.componentOrder != ComponentOrder::BODY_FIRST
                || ep_params.layout.gadgetLength != ep_params.gadgetParams.length
                || ep_params.layout.gadgetBase != ep_params.gadgetParams.base) {
                throw invalid_argument("MV-FBS raw RGSW layout mismatch");
            }
            MvFbsKey key;
            key.bootstrappingKey.reserve(lwe_sk.s.size());
            auto total_start = Clock::now();
            auto step_start = Clock::now();
            size_t index = 0;
            for (uint64_t bit : lwe_sk.s) {
                key.bootstrappingKey.push_back(raw_rgsw_encrypt_bit(bit, rlwe_sk, ep_params, params.lweParams.sigma));
                index++;
                if (index == 1 || index % 16 == 0 || index == lwe_sk.s.size()) {
                    mv_fbs_perf_log("setup.keygen.mv_fbs_bsk_progress="
                        + to_string(index) + "/" + to_string(lwe_sk.s.size())
                        + ", last_chunk_ms=" + to_string(elapsed_ms(step_start))
                        + ", total_ms=" + to_string(elapsed_ms(total_start)));
                    step_start = Clock::now();
                }
            }
            return key;
        }
    }
}
