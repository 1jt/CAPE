#pragma once

#include "hom_trace.h"
#include "lwe.h"
#include "mv_fbs.h"
#include "scheme_switch.h"

#include <cstdint>
#include <utility>
#include <vector>

namespace seal {
    namespace fusepirc {
        struct CircuitBootstrapParams {
            LweParams lweParams;
            RawRlweParams rlweParams;
            // Final RawRGSW output gadget consumed by FUSE_PIR_C selector / row BlindRotate.
            GadgetParams outputGadgetParams;
            RgswLayout outputRgswLayout;
            RawExternalProductParams outputExternalProductParams;
            // Internal exact gadget used only by MV-FBS repeated CMUX.
            GadgetParams mvFbsCmuxGadgetParams;
            RgswLayout mvFbsCmuxRgswLayout;
            RawExternalProductParams mvFbsExternalProductParams;
            GadgetParams homTraceKeySwitchGadgetParams;
            GadgetParams schemeSwitchKeySwitchGadgetParams;
            // Backward-compatible aliases for the final output gadget.
            GadgetParams gadgetParams;
            RgswLayout rgswLayout;
            RawExternalProductParams externalProductParams;
            MvFbsParams mvFbsParams;
            HomTraceParams homTraceParams;
            SchemeSwitchParams schemeSwitchParams;
            std::uint32_t gadgetLength;
            std::uint64_t gadgetBase;
            std::uint32_t degree;
            std::uint64_t modulus;
        };

        struct CircuitBootstrapClientSecretState {
            LweSecretKey lweSk;
            RawRlweSecretKey rlweSk;
        };

        struct CircuitBootstrapEvaluationKey {
            MvFbsKey mvFbsKey;
            HomTraceKey homTraceKey;
            SchemeSwitchKey schemeSwitchKey;
        };

        struct CachedCircuitBootstrapEvaluationKey {
            CircuitBootstrapEvaluationKey coeffKey;
            std::vector<CachedRawRgswCipherNtt> mvFbsBootstrappingKeyNtt;
        };

        struct CircuitBootstrapWorkspace {
            std::uint32_t degree = 0;
            std::uint64_t modulus = 0;
            std::uint32_t gadgetLength = 0;
            std::uint64_t gadgetBase = 0;
            std::vector<std::uint64_t> outputValues;
            MvFbsTestPolynomialSet testPolySet;
            std::vector<RawRlweCipher> mvFbsOutputs;
            std::vector<RawRlweCipher> tracedDigits;
            RawNttWorkspace nttWorkspace;
        };

        struct CircuitBootstrapTiming {
            std::uint64_t mvFbsMs = 0;
            std::uint64_t homTraceMs = 0;
            std::uint64_t schemeSwitchMs = 0;
            std::uint64_t totalMs = 0;
        };

        CircuitBootstrapParams make_circuit_bootstrap_params(
            const LweParams &lwe_params, const RawRlweParams &rlwe_params,
            const GadgetParams &gadget_params, const RgswLayout &rgsw_layout);

        std::pair<CircuitBootstrapClientSecretState, CircuitBootstrapEvaluationKey> generate_circuit_bootstrap_keys(
            const CircuitBootstrapParams &params, double sigma);

        std::vector<std::uint64_t> build_rgsw_gadget_output_values(
            const GadgetParams &gadget_params, std::uint64_t modulus_q);

        CachedCircuitBootstrapEvaluationKey make_cached_circuit_bootstrap_key(
            CircuitBootstrapEvaluationKey key, const CircuitBootstrapParams &params);

        RawRgswCipher secure_lwe_to_rgsw(
            const LweCipher &lwe_bit, const CircuitBootstrapEvaluationKey &evaluation_key,
            const CircuitBootstrapParams &params);

        RawRgswCipher secure_lwe_to_rgsw_with_workspace(
            const LweCipher &lwe_bit, const CircuitBootstrapEvaluationKey &evaluation_key,
            const CircuitBootstrapParams &params, CircuitBootstrapWorkspace &workspace,
            CircuitBootstrapTiming *timing = nullptr);

        RawRgswCipher secure_lwe_to_rgsw_with_workspace_cached_ntt(
            const LweCipher &lwe_bit, const CachedCircuitBootstrapEvaluationKey &evaluation_key,
            const CircuitBootstrapParams &params, CircuitBootstrapWorkspace &workspace,
            CircuitBootstrapTiming *timing = nullptr);

        std::vector<RawRgswCipher> secure_lwe_bits_to_rgsw(
            const std::vector<LweCipher> &lwe_bits, const CircuitBootstrapEvaluationKey &evaluation_key,
            const CircuitBootstrapParams &params);

        std::vector<RawRgswCipher> secure_lwe_bits_to_rgsw_batch(
            const std::vector<LweCipher> &lwe_bits, const CircuitBootstrapEvaluationKey &evaluation_key,
            const CircuitBootstrapParams &params, const char *log_prefix = nullptr);

        std::vector<RawRgswCipher> secure_lwe_bits_to_rgsw_batch_cached_ntt(
            const std::vector<LweCipher> &lwe_bits, const CachedCircuitBootstrapEvaluationKey &evaluation_key,
            const CircuitBootstrapParams &params, const char *log_prefix = nullptr);
    }
}
