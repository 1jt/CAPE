#pragma once

#include "gadget.h"
#include "lwe.h"
#include "raw_cmux.h"

#include <cstdint>
#include <vector>

namespace seal {
    namespace fusepirc {
        struct ModSwitchedLwe {
            std::vector<std::int64_t> aBar;
            std::int64_t bBar;
            std::uint32_t rotationModulus;
        };

        struct MvFbsParams {
            LweParams lweParams;
            RawRlweParams rlweParams;
            GadgetParams gadgetParams;
            std::uint32_t outputDigitNum;
            std::uint32_t degree;
            std::uint64_t modulus;
            std::uint64_t lweModulus;
            std::uint32_t plaintextModulus;
            std::uint32_t rotationModulus;
            bool scaleByTraceInverse;
        };

        struct MvFbsKey {
            std::vector<RawRgswCipher> bootstrappingKey;
        };

        struct MvFbsTestPolynomialSet {
            std::vector<TorusPoly> testPolys;
            std::vector<std::uint64_t> outputValues;
        };

        void validate_mv_fbs_params(const MvFbsParams &params);

        std::uint64_t mul_mod_uint64(std::uint64_t a, std::uint64_t b, std::uint64_t modulus);

        std::uint64_t mod_inverse_uint64(std::uint64_t x, std::uint64_t modulus);

        std::uint64_t trace_inverse_scale_value(
            std::uint64_t output_value, std::uint32_t degree_n, std::uint64_t modulus_q);

        ModSwitchedLwe mod_switch_for_blind_rotation(const LweCipher &lwe, const MvFbsParams &params);

        std::uint64_t encode_trace_inverse_scaled_value(std::uint64_t output_value, const MvFbsParams &params);

        TorusPoly build_mv_fbs_bit_test_polynomial(std::uint64_t output_value, const MvFbsParams &params);

        MvFbsTestPolynomialSet build_mv_fbs_test_polynomial_set(
            const std::vector<std::uint64_t> &output_values, const MvFbsParams &params);

        RawRlweCipher init_mv_fbs_accumulator(
            const TorusPoly &test_poly, std::int64_t b_bar, const RawRlweParams &rlwe_params);

        RawRlweCipher cmux_blind_rotate_single_output(
            const RawRlweCipher &initial_acc, const ModSwitchedLwe &ms_lwe, const MvFbsKey &key,
            const MvFbsParams &params, const RawExternalProductParams &ep_params);

        RawRlweCipher cmux_blind_rotate_single_output_cached_ntt(
            const RawRlweCipher &initial_acc, const ModSwitchedLwe &ms_lwe,
            const std::vector<CachedRawRgswCipherNtt> &cached_bootstrapping_key, const MvFbsParams &params,
            const RawExternalProductParams &ep_params, RawNttWorkspace &workspace);

        std::vector<RawRlweCipher> mv_fbs_no_sample_extract(
            const LweCipher &lwe, const MvFbsKey &key, const MvFbsTestPolynomialSet &test_poly_set,
            const MvFbsParams &params, const RawExternalProductParams &ep_params);

        std::vector<RawRlweCipher> mv_fbs_no_sample_extract_cached_ntt(
            const LweCipher &lwe, const std::vector<CachedRawRgswCipherNtt> &cached_bootstrapping_key,
            const MvFbsTestPolynomialSet &test_poly_set, const MvFbsParams &params,
            const RawExternalProductParams &ep_params, RawNttWorkspace &workspace);

        MvFbsKey generate_mv_fbs_key(
            const LweSecretKey &lwe_sk, const RawRlweSecretKey &rlwe_sk, const MvFbsParams &params,
            const RawExternalProductParams &ep_params);
    }
}
