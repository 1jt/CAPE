#include "raw_external_product.h"
#include "raw_ntt.h"

#include <atomic>
#include <iostream>
#include <stdexcept>
#include <utility>

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

            RawRlweCipher raw_rlwe_mul_plain_poly(const RawRlweCipher &ct, const TorusPoly &plain) {
                validate_same_ring(ct.a, plain);
                return RawRlweCipher{
                    negacyclic_mul_poly_auto(ct.a, plain),
                    negacyclic_mul_poly_auto(ct.b, plain),
                    ct.params,
                    false,
                    ct.level
                };
            }

            void validate_cached_rgsw_ntt(
                const CachedRawRgswCipherNtt &cached_rgsw, const RawExternalProductParams &params) {
                validate_raw_external_product_params(params);
                if (cached_rgsw.params.degree != params.rlweParams.degree
                    || cached_rgsw.params.modulus != params.rlweParams.modulus
                    || cached_rgsw.layout.componentOrder != params.layout.componentOrder
                    || cached_rgsw.layout.gadgetLength != params.layout.gadgetLength
                    || cached_rgsw.layout.gadgetBase != params.layout.gadgetBase) {
                    throw invalid_argument("cached raw RGSW NTT params/layout mismatch");
                }
                if (cached_rgsw.components.size() != 2 * params.gadgetParams.length) {
                    throw invalid_argument("cached raw RGSW NTT component count mismatch");
                }
                for (const RawRlweCipherNtt &component : cached_rgsw.components) {
                    if (component.params.degree != params.rlweParams.degree
                        || component.params.modulus != params.rlweParams.modulus
                        || component.aNtt.size() != params.rlweParams.degree
                        || component.bNtt.size() != params.rlweParams.degree) {
                        throw invalid_argument("cached raw RGSW NTT component ring mismatch");
                    }
                }
            }
        }

        CachedRawRgswCipherNtt make_cached_raw_rgsw_ntt(
            const RawRgswCipher &rgsw, const RawNttParams &ntt_params) {
            if (rgsw.params.degree != ntt_params.degree || rgsw.params.modulus != ntt_params.modulus) {
                throw invalid_argument("cached raw RGSW NTT params mismatch");
            }
            CachedRawRgswCipherNtt cached;
            cached.layout = rgsw.layout;
            cached.params = rgsw.params;
            cached.components.reserve(rgsw.components.size());
            for (const RawRlweCipher &component : rgsw.components) {
                if (component.params.degree != rgsw.params.degree || component.params.modulus != rgsw.params.modulus
                    || component.isNttForm) {
                    throw invalid_argument("cached raw RGSW component params mismatch");
                }
                RawRlweCipherNtt cached_component;
                cached_component.params = component.params;
                forward_negacyclic_ntt_twisted(component.a, ntt_params, cached_component.aNtt);
                forward_negacyclic_ntt_twisted(component.b, ntt_params, cached_component.bNtt);
                cached.components.push_back(std::move(cached_component));
            }
            return cached;
        }

        vector<TorusPoly> raw_decompose_rlwe_for_external_product(
            const RawRlweCipher &ct, const GadgetParams &gadget_params, const RgswLayout &layout) {
            if (ct.isNttForm) {
                throw invalid_argument("raw external product requires coefficient-form RLWE input");
            }
            if (layout.componentOrder != ComponentOrder::BODY_FIRST) {
                throw invalid_argument("raw external product currently requires body-first RGSW layout");
            }
            // raw_external_product decomposition order = RGSW component order.
            // For FUSE_PIR_C phase = b - a*s and body-first RGSW components [g_j, s*g_j], decompose b first and -a second.
            vector<TorusPoly> decomposed;
            vector<TorusPoly> b_digits = gadget_decompose(ct.b, gadget_params);
            vector<TorusPoly> neg_a_digits = gadget_decompose(neg_mod(ct.a), gadget_params);
            decomposed.reserve(b_digits.size() + neg_a_digits.size());
            decomposed.insert(decomposed.end(), b_digits.begin(), b_digits.end());
            decomposed.insert(decomposed.end(), neg_a_digits.begin(), neg_a_digits.end());
            return decomposed;
        }

        RawRlweCipher raw_external_product(
            const RawRlweCipher &ct, const RawRgswCipher &rgsw, const RawExternalProductParams &params) {
            validate_raw_external_product_params(params);
            validate_raw_rgsw_cipher(rgsw, params);
            if (ct.params.degree != params.rlweParams.degree || ct.params.modulus != params.rlweParams.modulus
                || ct.isNttForm) {
                throw invalid_argument("raw external product input params mismatch");
            }
            vector<TorusPoly> decomposed = raw_decompose_rlwe_for_external_product(ct, params.gadgetParams,
                params.layout);
            if (decomposed.size() != rgsw.components.size()) {
                throw invalid_argument("raw external product decomposition / RGSW size mismatch");
            }
            RawRlweCipher acc{
                zero_poly(params.rlweParams.degree, params.rlweParams.modulus),
                zero_poly(params.rlweParams.degree, params.rlweParams.modulus),
                params.rlweParams,
                false,
                0
            };
            for (size_t i = 0; i < decomposed.size(); i++) {
                acc = raw_rlwe_add(acc, raw_rlwe_mul_plain_poly(rgsw.components[i], decomposed[i]));
            }
            return acc;
        }

        RawRlweCipher raw_external_product_cached_ntt(
            const RawRlweCipher &ct, const CachedRawRgswCipherNtt &cached_rgsw,
            const RawExternalProductParams &params, RawNttWorkspace &workspace) {
            validate_cached_rgsw_ntt(cached_rgsw, params);
            if (ct.params.degree != params.rlweParams.degree || ct.params.modulus != params.rlweParams.modulus
                || ct.isNttForm) {
                throw invalid_argument("cached raw external product input params mismatch");
            }
            vector<TorusPoly> decomposed = raw_decompose_rlwe_for_external_product(
                ct, params.gadgetParams, params.layout);
            if (decomposed.size() != cached_rgsw.components.size()) {
                throw invalid_argument("cached raw external product decomposition / RGSW size mismatch");
            }
            RawNttParams ntt_params = get_cached_raw_ntt_params(params.rlweParams.degree, params.rlweParams.modulus);
            workspace.accANtt.assign(params.rlweParams.degree, 0);
            workspace.accBNtt.assign(params.rlweParams.degree, 0);
            for (size_t i = 0; i < decomposed.size(); i++) {
                forward_negacyclic_ntt_twisted(decomposed[i], ntt_params, workspace.digitNtt);
                const RawRlweCipherNtt &component = cached_rgsw.components[i];
                for (uint32_t k = 0; k < params.rlweParams.degree; k++) {
                    workspace.accANtt[k] = add_uint_mod(
                        workspace.accANtt[k],
                        raw_ntt_mul_mod(workspace.digitNtt[k], component.aNtt[k], params.rlweParams.modulus),
                        params.rlweParams.modulus
                    );
                    workspace.accBNtt[k] = add_uint_mod(
                        workspace.accBNtt[k],
                        raw_ntt_mul_mod(workspace.digitNtt[k], component.bNtt[k], params.rlweParams.modulus),
                        params.rlweParams.modulus
                    );
                }
            }
            return RawRlweCipher{
                inverse_negacyclic_ntt_twisted(workspace.accANtt, ntt_params),
                inverse_negacyclic_ntt_twisted(workspace.accBNtt, ntt_params),
                params.rlweParams,
                false,
                ct.level
            };
        }
    }
}
