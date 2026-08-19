#pragma once

#include "raw_rlwe.h"

#include <cstdint>
#include <vector>

namespace seal {
    namespace fusepirc {
        struct GadgetParams {
            std::uint64_t base;
            std::uint32_t baseBitLength;
            std::uint32_t length;
            std::uint64_t modulus;
            bool exact;
            enum class ScaleMode {
                LOW_BITS_EXACT = 0,
                TORUS_APPROX_HIGH = 1
            } scaleMode = ScaleMode::LOW_BITS_EXACT;
        };

        struct GadgetSpec {
            std::uint64_t modulus;
            std::uint64_t base;
            std::uint32_t length;
            GadgetParams::ScaleMode scaleMode;
            std::vector<std::uint64_t> gadgetValues;
        };

        struct RawRlweGadgetDecomposition {
            std::vector<TorusPoly> aDigits;
            std::vector<TorusPoly> bDigits;
        };

        void validate_gadget_params(const GadgetParams &params);

        GadgetSpec make_gadget_spec(const GadgetParams &params);

        std::vector<std::uint64_t> gadget_values(const GadgetParams &params);

        std::vector<TorusPoly> gadget_decompose(const TorusPoly &poly, const GadgetParams &params);

        std::vector<TorusPoly> gadget_decompose_exact(const TorusPoly &poly, const GadgetParams &params);

        std::vector<TorusPoly> gadget_decompose_torus_scaled(const TorusPoly &poly, const GadgetParams &params);

        TorusPoly gadget_compose_exact(const std::vector<TorusPoly> &digits, const GadgetParams &params);

        TorusPoly gadget_compose(const std::vector<TorusPoly> &digits, const GadgetParams &params);

        RawRlweGadgetDecomposition gadget_decompose_rlwe(const RawRlweCipher &ct, const GadgetParams &params);
    }
}
