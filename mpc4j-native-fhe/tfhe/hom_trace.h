#pragma once

#include "raw_automorphism_key.h"

namespace seal {
    namespace fusepirc {
        struct HomTraceParams {
            RawRlweParams params;
            GadgetParams gadgetParams;
            std::uint32_t degree;
            std::uint64_t modulus;
            std::vector<std::uint32_t> automorphismExponents;
            bool inputAlreadyTraceInverseScaled;
        };

        struct HomTraceKey {
            RawRlweParams params;
            GadgetParams gadgetParams;
            std::vector<RawAutomorphismKey> automorphismKeys;
        };

        HomTraceParams make_hom_trace_params(const RawRlweParams &rlwe_params, const GadgetParams &gadget_params);

        HomTraceKey generate_hom_trace_key(
            const RawRlweSecretKey &sk, const HomTraceParams &params, double sigma);

        RawRlweCipher hom_trace(const RawRlweCipher &input, const HomTraceKey &key, const HomTraceParams &params);

        std::vector<RawRlweCipher> hom_trace_many(
            const std::vector<RawRlweCipher> &inputs, const HomTraceKey &key, const HomTraceParams &params);
    }
}
