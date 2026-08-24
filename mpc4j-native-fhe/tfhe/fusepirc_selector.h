#pragma once

#include "circuit_bootstrap.h"
#include "raw_rlwe_prime.h"

#include <cstdint>
#include <vector>

namespace seal {
    namespace fusepirc {
        RawRlweCipher trivial_raw_rlwe_monomial(
            std::uint32_t exponent, const RawRlweParams &params);

        RawRlweCipher trivial_raw_rlwe_constant(
            std::uint64_t value, const RawRlweParams &params);

        RawRlweCipher build_monomial_selector_from_rgsw_bits(
            const std::vector<RawRgswCipher> &col_bits, std::uint32_t col_num,
            const RawRlweParams &rlwe_params, const RawExternalProductParams &ep_params,
            const RgswLayout &rgsw_layout);

        std::vector<RawRlwePrimeCipher> build_one_hot_selector_from_rgsw_bits(
            const std::vector<RawRgswCipher> &index_bits, std::uint32_t bound,
            const RawRlweParams &rlwe_params, const GadgetParams &gadget_params,
            const RawExternalProductParams &ep_params, const RgswLayout &rgsw_layout);

        RawRlwePrimeCipher select_column_with_one_hot_selector(
            const std::vector<RawRlwePrimeCipher> &selector, const std::vector<TorusPoly> &columns,
            std::uint32_t col_num, const RawRlweParams &rlwe_params, const GadgetParams &gadget_params);

        RawRlweCipher select_plain_column_with_one_hot_selector_to_raw_rlwe(
            const std::vector<RawRlwePrimeCipher> &selector, const std::vector<TorusPoly> &columns,
            std::uint32_t col_num, const RawRlweParams &rlwe_params, const GadgetParams &gadget_params);

        RawRlweCipher select_plain_column_with_one_hot_selector_to_raw_rlwe_cached_digits(
            const std::vector<RawRlwePrimeCipher> &selector,
            const std::vector<std::vector<TorusPoly>> &decomposed_columns,
            std::uint32_t col_num, const RawRlweParams &rlwe_params, const GadgetParams &gadget_params);

        RawRlweCipher select_plain_column_from_cached_rgsw_bits(
            const std::vector<CachedRawRgswCipherNtt> &index_bits_ntt,
            const std::vector<TorusPoly> &columns, std::uint32_t col_num,
            const RawRlweParams &rlwe_params, const RawExternalProductParams &ep_params,
            const RgswLayout &rgsw_layout, RawNttWorkspace &workspace);

        RawRlweCipher blind_rotate_row_to_zero_from_rgsw_bits(
            const RawRlweCipher &packed_column, const std::vector<RawRgswCipher> &row_bits,
            std::uint32_t row_num, std::uint32_t row_stride, const RawRlweParams &rlwe_params,
            const RawExternalProductParams &ep_params, const RgswLayout &rgsw_layout);

        RawRlweCipher blind_rotate_row_to_zero_from_cached_rgsw_bits(
            const RawRlweCipher &packed_column, const std::vector<CachedRawRgswCipherNtt> &row_bits_ntt,
            std::uint32_t row_num, std::uint32_t row_stride, const RawRlweParams &rlwe_params,
            const RawExternalProductParams &ep_params, const RgswLayout &rgsw_layout,
            RawNttWorkspace &workspace);
    }
}
