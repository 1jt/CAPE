#include "lwe.h"
#include "seal/util/hash.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <limits>
#include <random>
#include <stdexcept>

using namespace std;

namespace seal {
    namespace fusepirc {
        namespace {
            constexpr uint32_t COMPRESSED_QUERY_MAGIC = 0x4F584D50;
            constexpr uint32_t COMPRESSED_QUERY_VERSION = 1;
            constexpr size_t SEED_BYTE_LENGTH = 32;

            uint32_t byte_length_for_modulus(uint64_t modulus) {
                if (modulus <= 1) {
                    throw invalid_argument("modulus must be greater than one");
                }
                uint32_t bit_length = 64 - static_cast<uint32_t>(__builtin_clzll(modulus - 1));
                return (bit_length + 7) / 8;
            }

            uint64_t add_mod(uint64_t a, uint64_t b, uint64_t q) {
                return static_cast<uint64_t>((static_cast<__uint128_t>(a) + b) % q);
            }

            uint64_t sub_mod(uint64_t a, uint64_t b, uint64_t q) {
                return a >= b ? a - b : static_cast<uint64_t>(static_cast<__uint128_t>(a) + q - b);
            }

            uint64_t add_signed_mod(uint64_t a, int64_t e, uint64_t q) {
                if (e >= 0) {
                    return add_mod(a, static_cast<uint64_t>(e), q);
                }
                uint64_t magnitude = static_cast<uint64_t>(-e);
                return sub_mod(a, magnitude % q, q);
            }

            uint64_t inner_product_binary_secret(const vector<uint64_t> &a, const LweSecretKey &sk, uint64_t q) {
                if (a.size() != sk.s.size()) {
                    throw invalid_argument("LWE a vector and secret key size mismatch");
                }
                uint64_t value = 0;
                for (size_t i = 0; i < a.size(); i++) {
                    if (sk.s[i] != 0) {
                        value = add_mod(value, a[i], q);
                    }
                }
                return value;
            }

            void put_u32(vector<uint8_t> &out, uint32_t value) {
                out.push_back(static_cast<uint8_t>(value >> 24));
                out.push_back(static_cast<uint8_t>(value >> 16));
                out.push_back(static_cast<uint8_t>(value >> 8));
                out.push_back(static_cast<uint8_t>(value));
            }

            void put_u64(vector<uint8_t> &out, uint64_t value) {
                for (int shift = 56; shift >= 0; shift -= 8) {
                    out.push_back(static_cast<uint8_t>(value >> shift));
                }
            }

            uint32_t read_u32(const vector<uint8_t> &in, size_t &offset) {
                if (offset + sizeof(uint32_t) > in.size()) {
                    throw invalid_argument("truncated uint32");
                }
                uint32_t value = 0;
                for (int i = 0; i < 4; i++) {
                    value = (value << 8) | in[offset++];
                }
                return value;
            }

            uint64_t read_u64(const vector<uint8_t> &in, size_t &offset) {
                if (offset + sizeof(uint64_t) > in.size()) {
                    throw invalid_argument("truncated uint64");
                }
                uint64_t value = 0;
                for (int i = 0; i < 8; i++) {
                    value = (value << 8) | in[offset++];
                }
                return value;
            }

            void put_uint(vector<uint8_t> &out, uint64_t value, uint32_t byte_length) {
                if (byte_length == 0 || byte_length > sizeof(uint64_t)) {
                    throw invalid_argument("invalid integer byte length");
                }
                for (int shift = static_cast<int>((byte_length - 1) * 8); shift >= 0; shift -= 8) {
                    out.push_back(static_cast<uint8_t>(value >> shift));
                }
            }

            uint64_t read_uint(const vector<uint8_t> &in, size_t &offset, uint32_t byte_length) {
                if (byte_length == 0 || byte_length > sizeof(uint64_t)
                    || offset + byte_length > in.size()) {
                    throw invalid_argument("truncated variable-width integer");
                }
                uint64_t value = 0;
                for (uint32_t i = 0; i < byte_length; i++) {
                    value = (value << 8) | in[offset++];
                }
                return value;
            }

            vector<uint64_t> bytes_to_u64_words(const vector<uint8_t> &seed, uint64_t domain, uint64_t counter) {
                vector<uint64_t> words;
                words.reserve((seed.size() + 7) / 8 + 3);
                words.push_back(UINT64_C(0x4F58544D502D4C57));
                words.push_back(domain);
                words.push_back(counter);
                uint64_t current = 0;
                int byte_count = 0;
                for (uint8_t b : seed) {
                    current = (current << 8) | b;
                    byte_count++;
                    if (byte_count == 8) {
                        words.push_back(current);
                        current = 0;
                        byte_count = 0;
                    }
                }
                if (byte_count > 0) {
                    current <<= 8 * (8 - byte_count);
                    words.push_back(current);
                }
                return words;
            }

            vector<uint8_t> random_seed() {
                random_device rd;
                vector<uint8_t> seed(SEED_BYTE_LENGTH);
                for (uint8_t &byte : seed) {
                    byte = static_cast<uint8_t>(rd());
                }
                return seed;
            }

            int64_t sample_nonzero_centered_error(double sigma) {
                random_device rd;
                mt19937_64 rng((static_cast<uint64_t>(rd()) << 32) ^ rd());
                normal_distribution<double> distribution(0.0, sigma);
                int64_t error = 0;
                while (error == 0) {
                    error = static_cast<int64_t>(llround(distribution(rng)));
                }
                return error;
            }
        }

        LweSecretKey binary_lwe_keygen(const LweParams &params) {
            if (params.n == 0 || params.q <= 1 || params.delta == 0 || params.sigma <= 0) {
                throw invalid_argument("invalid LWE params");
            }
            random_device rd;
            LweSecretKey sk;
            sk.s.resize(params.n);
            for (uint64_t &bit : sk.s) {
                bit = rd() & 1U;
            }
            return sk;
        }

        vector<uint64_t> prg_expand_lwe_a(const vector<uint8_t> &seed, uint64_t domain, uint32_t n, uint64_t q) {
            if (seed.empty() || n == 0 || q <= 1) {
                throw invalid_argument("invalid LWE PRG input");
            }
            vector<uint64_t> a(n);
            uint32_t generated = 0;
            uint64_t counter = 0;
            while (generated < n) {
                auto input = bytes_to_u64_words(seed, domain, counter++);
                util::HashFunction::hash_block_type digest;
                util::HashFunction::hash(input.data(), input.size(), digest);
                for (uint64_t word : digest) {
                    if (generated == n) {
                        break;
                    }
                    a[generated++] = word % q;
                }
            }
            return a;
        }

        LweCipher lwe_encrypt_bit(
            uint64_t bit, const LweSecretKey &sk, const LweParams &params, const vector<uint8_t> &seed,
            uint64_t domain) {
            if (bit > 1) {
                throw invalid_argument("LWE plaintext bit must be 0 or 1");
            }
            if (params.delta != params.q / 2) {
                throw invalid_argument("FUSE_PIR_C LWE bit encoding requires delta = q / 2");
            }
            LweCipher cipher;
            cipher.a = prg_expand_lwe_a(seed, domain, params.n, params.q);
            int64_t error = sample_nonzero_centered_error(params.sigma);
            uint64_t b = inner_product_binary_secret(cipher.a, sk, params.q);
            if (bit == 1) {
                b = add_mod(b, params.delta, params.q);
            }
            cipher.b = add_signed_mod(b, error, params.q);
            return cipher;
        }

        uint64_t lwe_decrypt_phase(const LweCipher &lwe, const LweSecretKey &sk, const LweParams &params) {
            uint64_t inner = inner_product_binary_secret(lwe.a, sk, params.q);
            return sub_mod(lwe.b, inner, params.q);
        }

        uint64_t lwe_decrypt_bit(const LweCipher &lwe, const LweSecretKey &sk, const LweParams &params) {
            uint64_t phase = lwe_decrypt_phase(lwe, sk, params);
            uint64_t q4 = params.q / 4;
            uint64_t three_q4 = params.q - q4;
            return phase >= q4 && phase < three_q4 ? 1 : 0;
        }

        vector<uint8_t> serialize_lwe_secret_key(const LweSecretKey &sk) {
            vector<uint8_t> out;
            put_u32(out, static_cast<uint32_t>(sk.s.size()));
            for (uint64_t bit : sk.s) {
                put_u64(out, bit);
            }
            return out;
        }

        LweSecretKey deserialize_lwe_secret_key(const vector<uint8_t> &encoded) {
            size_t offset = 0;
            uint32_t n = read_u32(encoded, offset);
            LweSecretKey sk;
            sk.s.resize(n);
            for (uint32_t i = 0; i < n; i++) {
                sk.s[i] = read_u64(encoded, offset);
                if (sk.s[i] != 0 && sk.s[i] != 1) {
                    throw invalid_argument("LWE secret key must be binary");
                }
            }
            if (offset != encoded.size()) {
                throw invalid_argument("extra bytes in LWE secret key");
            }
            return sk;
        }

        vector<uint8_t> serialize_compressed_lwe_bits(const CompressedLweBits &query) {
            if (query.version != COMPRESSED_QUERY_VERSION) {
                throw invalid_argument("unsupported compressed LWE query version");
            }
            uint32_t expected_b_element_byte_length = byte_length_for_modulus(query.q);
            if (query.b_element_byte_length != expected_b_element_byte_length) {
                throw invalid_argument("compressed LWE b element byte length does not match modulus");
            }
            uint32_t expected_bit_num = query.bff_hash_num * (query.row_bit_num + query.col_bit_num);
            if (query.b_array.size() != expected_bit_num) {
                throw invalid_argument("compressed LWE b array size mismatch");
            }
            vector<uint8_t> out;
            out.reserve(9 * sizeof(uint32_t) + sizeof(uint64_t) + query.seed.size()
                + query.b_array.size() * query.b_element_byte_length);
            put_u32(out, COMPRESSED_QUERY_MAGIC);
            put_u32(out, query.version);
            put_u32(out, query.row_bit_num);
            put_u32(out, query.col_bit_num);
            put_u32(out, query.bff_hash_num);
            put_u32(out, query.lwe_dimension);
            put_u64(out, query.q);
            put_u32(out, query.b_element_byte_length);
            put_u32(out, static_cast<uint32_t>(query.seed.size()));
            out.insert(out.end(), query.seed.begin(), query.seed.end());
            put_u32(out, static_cast<uint32_t>(query.b_array.size() * query.b_element_byte_length));
            for (uint64_t b : query.b_array) {
                if (b >= query.q) {
                    throw invalid_argument("compressed LWE b element exceeds modulus");
                }
                put_uint(out, b, query.b_element_byte_length);
            }
            return out;
        }

        CompressedLweBits deserialize_compressed_lwe_bits(const vector<uint8_t> &encoded) {
            size_t offset = 0;
            if (read_u32(encoded, offset) != COMPRESSED_QUERY_MAGIC) {
                throw invalid_argument("invalid FUSE_PIR_C compressed query magic");
            }
            CompressedLweBits query;
            query.version = read_u32(encoded, offset);
            query.row_bit_num = read_u32(encoded, offset);
            query.col_bit_num = read_u32(encoded, offset);
            query.bff_hash_num = read_u32(encoded, offset);
            query.lwe_dimension = read_u32(encoded, offset);
            query.q = read_u64(encoded, offset);
            query.b_element_byte_length = read_u32(encoded, offset);
            uint32_t expected_b_element_byte_length = byte_length_for_modulus(query.q);
            if (query.b_element_byte_length != expected_b_element_byte_length) {
                throw invalid_argument("compressed LWE b element byte length does not match modulus");
            }
            uint32_t seed_size = read_u32(encoded, offset);
            if (offset + seed_size > encoded.size()) {
                throw invalid_argument("truncated FUSE_PIR_C compressed query seed");
            }
            query.seed.assign(encoded.begin() + static_cast<ptrdiff_t>(offset),
                encoded.begin() + static_cast<ptrdiff_t>(offset + seed_size));
            offset += seed_size;
            uint32_t b_array_byte_length = read_u32(encoded, offset);
            if (b_array_byte_length % query.b_element_byte_length != 0
                || offset + b_array_byte_length > encoded.size()) {
                throw invalid_argument("invalid FUSE_PIR_C compressed query b array length");
            }
            uint32_t b_count = b_array_byte_length / query.b_element_byte_length;
            query.b_array.resize(b_count);
            for (uint32_t i = 0; i < b_count; i++) {
                query.b_array[i] = read_uint(encoded, offset, query.b_element_byte_length);
                if (query.b_array[i] >= query.q) {
                    throw invalid_argument("compressed LWE b element exceeds modulus");
                }
            }
            if (offset != encoded.size()) {
                throw invalid_argument("extra bytes in FUSE_PIR_C compressed query");
            }
            return query;
        }

        vector<LweCipher> recover_lwe_bits_from_compressed_query(const CompressedLweBits &query) {
            vector<LweCipher> result;
            uint32_t expected_bit_num = query.bff_hash_num * (query.row_bit_num + query.col_bit_num);
            if (query.b_array.size() != expected_bit_num) {
                throw invalid_argument("compressed query b array size mismatch");
            }
            result.reserve(query.b_array.size());
            size_t b_index = 0;
            for (uint32_t hash_position = 0; hash_position < query.bff_hash_num; hash_position++) {
                for (uint32_t bit_index = 0; bit_index < query.col_bit_num; bit_index++) {
                    LweCipher cipher;
                    cipher.a = prg_expand_lwe_a(query.seed, make_lwe_domain(hash_position, SelectorType::COL,
                        bit_index), query.lwe_dimension, query.q);
                    cipher.b = query.b_array[b_index++];
                    result.push_back(std::move(cipher));
                }
                for (uint32_t bit_index = 0; bit_index < query.row_bit_num; bit_index++) {
                    LweCipher cipher;
                    cipher.a = prg_expand_lwe_a(query.seed, make_lwe_domain(hash_position, SelectorType::ROW,
                        bit_index), query.lwe_dimension, query.q);
                    cipher.b = query.b_array[b_index++];
                    result.push_back(std::move(cipher));
                }
            }
            return result;
        }

        uint64_t make_lwe_domain(uint32_t hash_position, SelectorType selector_type, uint32_t bit_index) {
            if (hash_position >= 3) {
                throw invalid_argument("FUSE_PIR_C hash position must be in {0,1,2}");
            }
            return (static_cast<uint64_t>(hash_position) << 32)
                | (static_cast<uint64_t>(static_cast<uint8_t>(selector_type)) << 24)
                | bit_index;
        }

        vector<uint8_t> make_random_lwe_seed() {
            return random_seed();
        }
    }
}
