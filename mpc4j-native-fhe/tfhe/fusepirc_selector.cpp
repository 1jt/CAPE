#include "fusepirc_selector.h"
#include "raw_ntt.h"

#include <atomic>
#include <iostream>
#include <stdexcept>

using namespace std;

namespace seal {
    namespace fusepirc {
        namespace {
            uint64_t add_uint_mod(uint64_t a, uint64_t b, uint64_t modulus) {
                return static_cast<uint64_t>((static_cast<__uint128_t>(a) + b) % modulus);
            }

            uint64_t mul_uint_mod(uint64_t a, uint64_t b, uint64_t modulus) {
                return static_cast<uint64_t>((static_cast<__uint128_t>(a) * b) % modulus);
            }

            TorusPoly negacyclic_mul_poly(const TorusPoly &poly_a, const TorusPoly &poly_b) {
                validate_same_ring(poly_a, poly_b);
                TorusPoly out = zero_poly(poly_a.degree, poly_a.modulus);
                uint64_t two_degree = static_cast<uint64_t>(2) * poly_a.degree;
                for (uint32_t i = 0; i < poly_a.degree; i++) {
                    for (uint32_t j = 0; j < poly_b.degree; j++) {
                        uint64_t mapped = (static_cast<uint64_t>(i) + j) % two_degree;
                        uint64_t product = mul_uint_mod(poly_a.coeffs[i], poly_b.coeffs[j], poly_a.modulus);
                        if (mapped >= poly_a.degree) {
                            mapped -= poly_a.degree;
                            product = product == 0 ? 0 : poly_a.modulus - product;
                        }
                        out.coeffs[static_cast<uint32_t>(mapped)] = add_uint_mod(
                            out.coeffs[static_cast<uint32_t>(mapped)], product, poly_a.modulus
                        );
                    }
                }
                return out;
            }

            TorusPoly negacyclic_mul_poly_auto(const TorusPoly &poly_a, const TorusPoly &poly_b) {
                validate_same_ring(poly_a, poly_b);
                if (can_use_raw_ntt(poly_a.degree, poly_a.modulus)) {
                    return negacyclic_ntt_mul(
                        poly_a, poly_b, get_cached_raw_ntt_params(poly_a.degree, poly_a.modulus));
                }
                return negacyclic_mul_poly(poly_a, poly_b);
            }

            RawRlweCipher raw_rlwe_mul_plain_poly_local(const RawRlweCipher &ct, const TorusPoly &plain) {
                validate_same_ring(ct.a, plain);
                if (ct.isNttForm) {
                    throw invalid_argument("selector plaintext multiplication requires coefficient-form RawRLWE");
                }
                return RawRlweCipher{
                    negacyclic_mul_poly_auto(ct.a, plain),
                    negacyclic_mul_poly_auto(ct.b, plain),
                    ct.params,
                    false,
                    ct.level
                };
            }

            uint32_t ceil_log2_bound(uint32_t bound) {
                if (bound == 0) {
                    throw invalid_argument("selector bound must be positive");
                }
                uint32_t bit_num = 0;
                uint32_t value = 1;
                while (value < bound) {
                    if (value > (UINT32_MAX >> 1)) {
                        throw invalid_argument("selector bound overflow");
                    }
                    value <<= 1;
                    bit_num++;
                }
                return bit_num;
            }

            void validate_selector_common(
                const RawRlweParams &rlwe_params, const RawExternalProductParams &ep_params,
                const RgswLayout &rgsw_layout) {
                validate_raw_rlwe_params(rlwe_params);
                validate_raw_external_product_params(ep_params);
                if (ep_params.rlweParams.degree != rlwe_params.degree
                    || ep_params.rlweParams.modulus != rlwe_params.modulus) {
                    throw invalid_argument("selector external product RLWE params mismatch");
                }
                if (ep_params.layout.gadgetLength != rgsw_layout.gadgetLength
                    || ep_params.layout.gadgetBase != rgsw_layout.gadgetBase
                    || ep_params.layout.componentOrder != rgsw_layout.componentOrder) {
                    throw invalid_argument("selector RGSW layout mismatch");
                }
            }

            void validate_selector_bit(
                const RawRgswCipher &bit, const RawExternalProductParams &ep_params,
                const RgswLayout &rgsw_layout) {
                validate_raw_rgsw_cipher(bit, ep_params);
                validate_raw_rgsw_layout_for_external_product(bit, rgsw_layout);
            }
        }

        RawRlweCipher trivial_raw_rlwe_monomial(uint32_t exponent, const RawRlweParams &params) {
            validate_raw_rlwe_params(params);
            TorusPoly monomial = constant_poly(1, params.degree, params.modulus);
            monomial = negacyclic_mul_monomial(monomial, static_cast<int64_t>(exponent));
            return RawRlweCipher{
                zero_poly(params.degree, params.modulus),
                monomial,
                params,
                false,
                0
            };
        }

        RawRlweCipher trivial_raw_rlwe_constant(uint64_t value, const RawRlweParams &params) {
            validate_raw_rlwe_params(params);
            return RawRlweCipher{
                zero_poly(params.degree, params.modulus),
                constant_poly(value, params.degree, params.modulus),
                params,
                false,
                0
            };
        }

        RawRlweCipher build_monomial_selector_from_rgsw_bits(
            const vector<RawRgswCipher> &col_bits, uint32_t col_num, const RawRlweParams &rlwe_params,
            const RawExternalProductParams &ep_params, const RgswLayout &rgsw_layout) {
            // This helper is not the Pirouette-style selector used by FUSE_PIR_C.
            // FUSE_PIR_C uses build_one_hot_selector_from_rgsw_bits.
            validate_selector_common(rlwe_params, ep_params, rgsw_layout);
            if (col_num == 0) {
                throw invalid_argument("column selector colNum must be positive");
            }
            if (col_num > rlwe_params.degree) {
                throw invalid_argument("column selector colNum exceeds raw RLWE degree");
            }
            uint32_t bit_num = ceil_log2_bound(col_num);
            if (col_bits.size() != bit_num) {
                throw invalid_argument("column selector bit count mismatch");
            }
            RawRlweCipher cur = trivial_raw_rlwe_monomial(0, rlwe_params);
            for (uint32_t j = 0; j < bit_num; j++) {
                validate_selector_bit(col_bits[j], ep_params, rgsw_layout);
                uint64_t shift = UINT64_C(1) << j;
                if (shift > static_cast<uint64_t>(INT64_MAX)) {
                    throw invalid_argument("column selector shift overflow");
                }
                RawRlweCipher shifted = raw_rlwe_mul_monomial(cur, static_cast<int64_t>(shift));
                cur = raw_cmux(col_bits[j], shifted, cur, ep_params);
            }
            return cur;
        }

        vector<RawRlwePrimeCipher> build_one_hot_selector_from_rgsw_bits(
            const vector<RawRgswCipher> &index_bits, uint32_t bound, const RawRlweParams &rlwe_params,
            const GadgetParams &gadget_params, const RawExternalProductParams &ep_params,
            const RgswLayout &rgsw_layout) {
            validate_selector_common(rlwe_params, ep_params, rgsw_layout);
            validate_gadget_params(gadget_params);
            if (gadget_params.length != ep_params.gadgetParams.length
                || gadget_params.base != ep_params.gadgetParams.base
                || gadget_params.modulus != ep_params.gadgetParams.modulus) {
                throw invalid_argument("one-hot selector gadget params mismatch");
            }
            uint32_t bit_num = ceil_log2_bound(bound);
            if (index_bits.size() != bit_num) {
                throw invalid_argument("one-hot selector bit count mismatch");
            }
            vector<RawRlwePrimeCipher> nodes;
            nodes.push_back(trivial_raw_rlwe_prime_constant(1, rlwe_params, gadget_params));
            for (uint32_t rev = 0; rev < bit_num; rev++) {
                uint32_t j = bit_num - 1 - rev;
                validate_selector_bit(index_bits[j], ep_params, rgsw_layout);
                vector<RawRlwePrimeCipher> next_nodes;
                next_nodes.reserve(nodes.size() * 2);
                for (const RawRlwePrimeCipher &node : nodes) {
                    RawRlwePrimeCipher selected_one = raw_rgsw_mul_rlwe_prime(
                        index_bits[j], node, ep_params, rgsw_layout
                    );
                    RawRlwePrimeCipher selected_zero = raw_rlwe_prime_sub(node, selected_one);
                    next_nodes.push_back(selected_zero);
                    next_nodes.push_back(selected_one);
                }
                nodes = next_nodes;
            }
            if (nodes.size() < bound) {
                throw invalid_argument("one-hot selector leaf count below bound");
            }
            nodes.resize(bound);
            return nodes;
        }

        RawRlwePrimeCipher select_column_with_one_hot_selector(
            const vector<RawRlwePrimeCipher> &selector, const vector<TorusPoly> &columns,
            uint32_t col_num, const RawRlweParams &rlwe_params, const GadgetParams &gadget_params) {
            validate_raw_rlwe_params(rlwe_params);
            validate_gadget_params(gadget_params);
            if (col_num == 0 || selector.size() < col_num || columns.size() < col_num) {
                throw invalid_argument("one-hot column selection size mismatch");
            }
            RawRlwePrimeCipher selected = raw_rlwe_prime_zero(rlwe_params, gadget_params);
            for (uint32_t c = 0; c < col_num; c++) {
                validate_raw_rlwe_prime_cipher(selector[c]);
                validate_torus_poly(columns[c]);
                if (columns[c].degree != rlwe_params.degree || columns[c].modulus != rlwe_params.modulus) {
                    throw invalid_argument("one-hot column plaintext ring mismatch");
                }
                selected = raw_rlwe_prime_add(selected, raw_rlwe_prime_mul_plain_poly(selector[c], columns[c]));
            }
            return selected;
        }

        RawRlweCipher select_plain_column_with_one_hot_selector_to_raw_rlwe(
            const vector<RawRlwePrimeCipher> &selector, const vector<TorusPoly> &columns,
            uint32_t col_num, const RawRlweParams &rlwe_params, const GadgetParams &gadget_params) {
            validate_raw_rlwe_params(rlwe_params);
            validate_gadget_params(gadget_params);
            if (gadget_params.modulus != rlwe_params.modulus) {
                throw invalid_argument("one-hot raw column selection gadget modulus mismatch");
            }
            if (col_num == 0 || selector.size() < col_num || columns.size() < col_num) {
                throw invalid_argument("one-hot raw column selection size mismatch");
            }
            RawRlweCipher selected{
                zero_poly(rlwe_params.degree, rlwe_params.modulus),
                zero_poly(rlwe_params.degree, rlwe_params.modulus),
                rlwe_params,
                false,
                0
            };
            for (uint32_t c = 0; c < col_num; c++) {
                validate_raw_rlwe_prime_cipher(selector[c]);
                validate_torus_poly(columns[c]);
                if (columns[c].degree != rlwe_params.degree || columns[c].modulus != rlwe_params.modulus) {
                    throw invalid_argument("one-hot raw column plaintext ring mismatch");
                }
                vector<TorusPoly> column_digits = gadget_decompose(columns[c], gadget_params);
                if (column_digits.size() != selector[c].digits.size()) {
                    throw invalid_argument("one-hot raw column digit count mismatch");
                }
                for (uint32_t j = 0; j < column_digits.size(); j++) {
                    selected = raw_rlwe_add(selected, raw_rlwe_mul_plain_poly_local(
                        selector[c].digits[j], column_digits[j]
                    ));
                }
            }
            return selected;
        }

        RawRlweCipher select_plain_column_with_one_hot_selector_to_raw_rlwe_cached_digits(
            const vector<RawRlwePrimeCipher> &selector, const vector<vector<TorusPoly>> &decomposed_columns,
            uint32_t col_num, const RawRlweParams &rlwe_params, const GadgetParams &gadget_params) {
            validate_raw_rlwe_params(rlwe_params);
            validate_gadget_params(gadget_params);
            if (gadget_params.modulus != rlwe_params.modulus) {
                throw invalid_argument("cached one-hot raw column selection gadget modulus mismatch");
            }
            if (col_num == 0 || selector.size() < col_num || decomposed_columns.size() < col_num) {
                throw invalid_argument("cached one-hot raw column selection size mismatch");
            }
            RawRlweCipher selected{
                zero_poly(rlwe_params.degree, rlwe_params.modulus),
                zero_poly(rlwe_params.degree, rlwe_params.modulus),
                rlwe_params,
                false,
                0
            };
            for (uint32_t c = 0; c < col_num; c++) {
                validate_raw_rlwe_prime_cipher(selector[c]);
                if (decomposed_columns[c].size() != selector[c].digits.size()
                    || decomposed_columns[c].size() != gadget_params.length) {
                    throw invalid_argument("cached one-hot raw column digit count mismatch");
                }
                for (uint32_t j = 0; j < decomposed_columns[c].size(); j++) {
                    validate_torus_poly(decomposed_columns[c][j]);
                    if (decomposed_columns[c][j].degree != rlwe_params.degree
                        || decomposed_columns[c][j].modulus != rlwe_params.modulus) {
                        throw invalid_argument("cached one-hot raw column plaintext ring mismatch");
                    }
                    selected = raw_rlwe_add(selected, raw_rlwe_mul_plain_poly_local(
                        selector[c].digits[j], decomposed_columns[c][j]
                    ));
                }
            }
            return selected;
        }

        RawRlweCipher blind_rotate_row_to_zero_from_rgsw_bits(
            const RawRlweCipher &packed_column, const vector<RawRgswCipher> &row_bits, uint32_t row_num,
            uint32_t row_stride, const RawRlweParams &rlwe_params, const RawExternalProductParams &ep_params,
            const RgswLayout &rgsw_layout) {
            validate_selector_common(rlwe_params, ep_params, rgsw_layout);
            if (packed_column.params.degree != rlwe_params.degree
                || packed_column.params.modulus != rlwe_params.modulus || packed_column.isNttForm) {
                throw invalid_argument("row selector packed column params mismatch");
            }
            if (row_num == 0) {
                throw invalid_argument("row selector rowNum must be positive");
            }
            if (row_stride == 0) {
                throw invalid_argument("row selector rowStride must be positive");
            }
            if (static_cast<uint64_t>(row_num) * row_stride > rlwe_params.degree) {
                throw invalid_argument("row selector packed rows exceed raw RLWE degree");
            }
            uint32_t bit_num = ceil_log2_bound(row_num);
            if (row_bits.size() != bit_num) {
                throw invalid_argument("row selector bit count mismatch");
            }
            RawRlweCipher cur = packed_column;
            for (uint32_t j = 0; j < bit_num; j++) {
                validate_selector_bit(row_bits[j], ep_params, rgsw_layout);
                uint64_t shift = (UINT64_C(1) << j) * static_cast<uint64_t>(row_stride);
                if (shift > static_cast<uint64_t>(INT64_MAX)) {
                    throw invalid_argument("row selector shift overflow");
                }
                RawRlweCipher shifted = raw_rlwe_mul_monomial(cur, -static_cast<int64_t>(shift));
                cur = raw_cmux(row_bits[j], shifted, cur, ep_params);
            }
            return cur;
        }

        RawRlweCipher blind_rotate_row_to_zero_from_cached_rgsw_bits(
            const RawRlweCipher &packed_column, const vector<CachedRawRgswCipherNtt> &row_bits_ntt,
            uint32_t row_num, uint32_t row_stride, const RawRlweParams &rlwe_params,
            const RawExternalProductParams &ep_params, const RgswLayout &rgsw_layout,
            RawNttWorkspace &workspace) {
            validate_selector_common(rlwe_params, ep_params, rgsw_layout);
            if (packed_column.params.degree != rlwe_params.degree
                || packed_column.params.modulus != rlwe_params.modulus || packed_column.isNttForm) {
                throw invalid_argument("cached row selector packed column params mismatch");
            }
            if (row_num == 0) {
                throw invalid_argument("cached row selector rowNum must be positive");
            }
            if (row_stride == 0) {
                throw invalid_argument("cached row selector rowStride must be positive");
            }
            if (static_cast<uint64_t>(row_num) * row_stride > rlwe_params.degree) {
                throw invalid_argument("cached row selector packed rows exceed raw RLWE degree");
            }
            uint32_t bit_num = ceil_log2_bound(row_num);
            if (row_bits_ntt.size() != bit_num) {
                throw invalid_argument("cached row selector bit count mismatch");
            }
            RawRlweCipher cur = packed_column;
            for (uint32_t j = 0; j < bit_num; j++) {
                uint64_t shift = (UINT64_C(1) << j) * static_cast<uint64_t>(row_stride);
                if (shift > static_cast<uint64_t>(INT64_MAX)) {
                    throw invalid_argument("cached row selector shift overflow");
                }
                RawRlweCipher shifted = raw_rlwe_mul_monomial(cur, -static_cast<int64_t>(shift));
                cur = raw_cmux_cached_ntt(row_bits_ntt[j], shifted, cur, ep_params, workspace);
            }
            return cur;
        }
    }
}
