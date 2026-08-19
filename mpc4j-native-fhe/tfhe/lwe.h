#pragma once

#include <cstdint>
#include <vector>

namespace seal {
    namespace fusepirc {
        enum class SelectorType : std::uint8_t {
            COL = 0,
            ROW = 1
        };

        struct LweParams {
            std::uint32_t n;
            std::uint64_t q;
            double sigma;
            std::uint64_t delta;
        };

        struct LweSecretKey {
            std::vector<std::uint64_t> s;
        };

        struct LweCipher {
            std::vector<std::uint64_t> a;
            std::uint64_t b;
        };

        struct CompressedLweBits {
            std::vector<std::uint8_t> seed;
            std::vector<std::uint64_t> b_array;
            std::uint32_t row_bit_num;
            std::uint32_t col_bit_num;
            std::uint32_t bff_hash_num;
            std::uint32_t lwe_dimension;
            std::uint64_t q;
            std::uint32_t b_element_byte_length;
            std::uint32_t version;
        };

        LweSecretKey binary_lwe_keygen(const LweParams &params);

        LweCipher lwe_encrypt_bit(
            std::uint64_t bit, const LweSecretKey &sk, const LweParams &params, const std::vector<std::uint8_t> &seed,
            std::uint64_t domain);

        std::uint64_t lwe_decrypt_phase(const LweCipher &lwe, const LweSecretKey &sk, const LweParams &params);

        std::uint64_t lwe_decrypt_bit(const LweCipher &lwe, const LweSecretKey &sk, const LweParams &params);

        std::vector<std::uint64_t> prg_expand_lwe_a(
            const std::vector<std::uint8_t> &seed, std::uint64_t domain, std::uint32_t n, std::uint64_t q);

        std::vector<std::uint8_t> serialize_lwe_secret_key(const LweSecretKey &sk);

        LweSecretKey deserialize_lwe_secret_key(const std::vector<std::uint8_t> &encoded);

        std::vector<std::uint8_t> serialize_compressed_lwe_bits(const CompressedLweBits &query);

        CompressedLweBits deserialize_compressed_lwe_bits(const std::vector<std::uint8_t> &encoded);

        std::vector<LweCipher> recover_lwe_bits_from_compressed_query(const CompressedLweBits &query);

        std::uint64_t make_lwe_domain(std::uint32_t hash_position, SelectorType selector_type, std::uint32_t bit_index);

        std::vector<std::uint8_t> make_random_lwe_seed();
    }
}
