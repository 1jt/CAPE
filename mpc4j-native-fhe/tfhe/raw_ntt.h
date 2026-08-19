#pragma once

#include "raw_poly.h"

#include <cstdint>

namespace seal {
    namespace fusepirc {
        struct RawNttParams {
            std::uint32_t degree;
            std::uint64_t modulus;
            std::uint64_t primitiveRoot2N;
            std::uint64_t primitiveRootN;
            std::uint64_t invDegree;
        };

        std::uint64_t raw_ntt_add_mod(std::uint64_t a, std::uint64_t b, std::uint64_t q);

        std::uint64_t raw_ntt_sub_mod(std::uint64_t a, std::uint64_t b, std::uint64_t q);

        std::uint64_t raw_ntt_mul_mod(std::uint64_t a, std::uint64_t b, std::uint64_t q);

        std::uint64_t raw_ntt_pow_mod(std::uint64_t a, std::uint64_t e, std::uint64_t q);

        std::uint64_t raw_ntt_inv_mod(std::uint64_t a, std::uint64_t q);

        std::uint64_t find_primitive_root_2n(std::uint32_t degree, std::uint64_t modulus);

        bool can_use_raw_ntt(std::uint32_t degree, std::uint64_t modulus);

        RawNttParams make_raw_ntt_params(std::uint32_t degree, std::uint64_t modulus);

        RawNttParams get_cached_raw_ntt_params(std::uint32_t degree, std::uint64_t modulus);

        void forward_negacyclic_ntt_twisted(
            const TorusPoly &poly, const RawNttParams &ntt_params, std::vector<std::uint64_t> &out);

        TorusPoly inverse_negacyclic_ntt_twisted(
            const std::vector<std::uint64_t> &values, const RawNttParams &ntt_params);

        TorusPoly negacyclic_ntt_mul(
            const TorusPoly &poly_a, const TorusPoly &poly_b, const RawNttParams &ntt_params);
    }
}
