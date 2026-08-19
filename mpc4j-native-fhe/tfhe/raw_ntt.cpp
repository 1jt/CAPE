#include "raw_ntt.h"

#include <algorithm>
#include <map>
#include <mutex>
#include <numeric>
#include <stdexcept>
#include <vector>

using namespace std;

namespace seal {
    namespace fusepirc {
        namespace {
            bool is_power_of_two(uint32_t value) {
                return value != 0 && (value & (value - 1)) == 0;
            }

            void bit_reverse(vector<uint64_t> &values) {
                size_t n = values.size();
                size_t j = 0;
                for (size_t i = 1; i < n; i++) {
                    size_t bit = n >> 1;
                    while ((j & bit) != 0) {
                        j ^= bit;
                        bit >>= 1;
                    }
                    j ^= bit;
                    if (i < j) {
                        swap(values[i], values[j]);
                    }
                }
            }

            void ntt_inplace(vector<uint64_t> &values, uint64_t root, uint64_t modulus) {
                size_t n = values.size();
                bit_reverse(values);
                for (size_t len = 2; len <= n; len <<= 1) {
                    uint64_t w_len = raw_ntt_pow_mod(root, static_cast<uint64_t>(n / len), modulus);
                    for (size_t i = 0; i < n; i += len) {
                        uint64_t w = 1;
                        for (size_t j = 0; j < len / 2; j++) {
                            uint64_t u = values[i + j];
                            uint64_t v = raw_ntt_mul_mod(values[i + j + len / 2], w, modulus);
                            values[i + j] = raw_ntt_add_mod(u, v, modulus);
                            values[i + j + len / 2] = raw_ntt_sub_mod(u, v, modulus);
                            w = raw_ntt_mul_mod(w, w_len, modulus);
                        }
                    }
                }
            }

            mutex g_raw_ntt_params_mutex;
            map<pair<uint32_t, uint64_t>, RawNttParams> g_raw_ntt_params_cache;
        }

        uint64_t raw_ntt_add_mod(uint64_t a, uint64_t b, uint64_t q) {
            return static_cast<uint64_t>((static_cast<__uint128_t>(a) + b) % q);
        }

        uint64_t raw_ntt_sub_mod(uint64_t a, uint64_t b, uint64_t q) {
            return a >= b ? a - b : static_cast<uint64_t>(static_cast<__uint128_t>(a) + q - b);
        }

        uint64_t raw_ntt_mul_mod(uint64_t a, uint64_t b, uint64_t q) {
            return static_cast<uint64_t>((static_cast<__uint128_t>(a) * b) % q);
        }

        uint64_t raw_ntt_pow_mod(uint64_t a, uint64_t e, uint64_t q) {
            if (q <= 1) {
                throw invalid_argument("raw NTT modulus must be greater than 1");
            }
            uint64_t result = 1 % q;
            uint64_t base = a % q;
            while (e != 0) {
                if ((e & 1U) != 0) {
                    result = raw_ntt_mul_mod(result, base, q);
                }
                base = raw_ntt_mul_mod(base, base, q);
                e >>= 1;
            }
            return result;
        }

        uint64_t raw_ntt_inv_mod(uint64_t a, uint64_t q) {
            if (q <= 1 || a % q == 0) {
                throw invalid_argument("invalid raw NTT modular inverse input");
            }
            __int128 t = 0;
            __int128 new_t = 1;
            __int128 r = q;
            __int128 new_r = a % q;
            while (new_r != 0) {
                __int128 quotient = r / new_r;
                __int128 tmp_t = t - quotient * new_t;
                t = new_t;
                new_t = tmp_t;
                __int128 tmp_r = r - quotient * new_r;
                r = new_r;
                new_r = tmp_r;
            }
            if (r != 1) {
                throw invalid_argument("raw NTT modular inverse does not exist");
            }
            if (t < 0) {
                t += q;
            }
            return static_cast<uint64_t>(t);
        }

        bool can_use_raw_ntt(uint32_t degree, uint64_t modulus) {
            if (!is_power_of_two(degree) || degree == 0 || modulus <= 2 || (modulus & 1U) == 0) {
                return false;
            }
            uint64_t two_degree = static_cast<uint64_t>(2) * degree;
            return modulus % two_degree == 1;
        }

        uint64_t find_primitive_root_2n(uint32_t degree, uint64_t modulus) {
            if (!can_use_raw_ntt(degree, modulus)) {
                throw invalid_argument("raw NTT requires power-of-two N and q mod 2N = 1");
            }
            uint64_t two_degree = static_cast<uint64_t>(2) * degree;
            uint64_t exponent = (modulus - 1) / two_degree;
            for (uint64_t candidate = 2; candidate < 1'000'000; candidate++) {
                uint64_t root = raw_ntt_pow_mod(candidate, exponent, modulus);
                if (root != 1
                    && raw_ntt_pow_mod(root, two_degree, modulus) == 1
                    && raw_ntt_pow_mod(root, degree, modulus) == modulus - 1) {
                    return root;
                }
            }
            throw invalid_argument("failed to find primitive 2N-th root for raw NTT");
        }

        RawNttParams make_raw_ntt_params(uint32_t degree, uint64_t modulus) {
            uint64_t root_2n = find_primitive_root_2n(degree, modulus);
            uint64_t root_n = raw_ntt_mul_mod(root_2n, root_2n, modulus);
            return RawNttParams{
                degree,
                modulus,
                root_2n,
                root_n,
                raw_ntt_inv_mod(degree % modulus, modulus)
            };
        }

        RawNttParams get_cached_raw_ntt_params(uint32_t degree, uint64_t modulus) {
            pair<uint32_t, uint64_t> key{degree, modulus};
            lock_guard<mutex> lock(g_raw_ntt_params_mutex);
            auto iter = g_raw_ntt_params_cache.find(key);
            if (iter != g_raw_ntt_params_cache.end()) {
                return iter->second;
            }
            RawNttParams params = make_raw_ntt_params(degree, modulus);
            g_raw_ntt_params_cache.emplace(key, params);
            return params;
        }

        void forward_negacyclic_ntt_twisted(
            const TorusPoly &poly, const RawNttParams &ntt_params, vector<uint64_t> &out) {
            validate_torus_poly(poly);
            if (poly.degree != ntt_params.degree || poly.modulus != ntt_params.modulus) {
                throw invalid_argument("raw NTT forward polynomial ring mismatch");
            }
            out.assign(poly.degree, 0);
            uint64_t psi_power = 1;
            for (uint32_t i = 0; i < poly.degree; i++) {
                out[i] = raw_ntt_mul_mod(poly.coeffs[i], psi_power, poly.modulus);
                psi_power = raw_ntt_mul_mod(psi_power, ntt_params.primitiveRoot2N, poly.modulus);
            }
            ntt_inplace(out, ntt_params.primitiveRootN, poly.modulus);
        }

        TorusPoly inverse_negacyclic_ntt_twisted(const vector<uint64_t> &values, const RawNttParams &ntt_params) {
            if (values.size() != ntt_params.degree) {
                throw invalid_argument("raw NTT inverse vector size mismatch");
            }
            vector<uint64_t> work(values.begin(), values.end());
            uint64_t inv_root = raw_ntt_inv_mod(ntt_params.primitiveRootN, ntt_params.modulus);
            ntt_inplace(work, inv_root, ntt_params.modulus);
            uint64_t inv_psi = raw_ntt_inv_mod(ntt_params.primitiveRoot2N, ntt_params.modulus);
            uint64_t inv_psi_power = 1;
            TorusPoly out = zero_poly(ntt_params.degree, ntt_params.modulus);
            for (uint32_t i = 0; i < ntt_params.degree; i++) {
                out.coeffs[i] = raw_ntt_mul_mod(
                    raw_ntt_mul_mod(work[i], ntt_params.invDegree, ntt_params.modulus),
                    inv_psi_power,
                    ntt_params.modulus
                );
                inv_psi_power = raw_ntt_mul_mod(inv_psi_power, inv_psi, ntt_params.modulus);
            }
            return out;
        }

        TorusPoly negacyclic_ntt_mul(
            const TorusPoly &poly_a, const TorusPoly &poly_b, const RawNttParams &ntt_params) {
            validate_same_ring(poly_a, poly_b);
            if (poly_a.degree != ntt_params.degree || poly_a.modulus != ntt_params.modulus) {
                throw invalid_argument("raw NTT polynomial ring mismatch");
            }
            vector<uint64_t> a(poly_a.degree);
            vector<uint64_t> b(poly_a.degree);
            forward_negacyclic_ntt_twisted(poly_a, ntt_params, a);
            forward_negacyclic_ntt_twisted(poly_b, ntt_params, b);
            for (uint32_t i = 0; i < poly_a.degree; i++) {
                a[i] = raw_ntt_mul_mod(a[i], b[i], poly_a.modulus);
            }
            return inverse_negacyclic_ntt_twisted(a, ntt_params);
        }
    }
}
