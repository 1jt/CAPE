#include "edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils.h"
#include "../../serialize.h"
#include "../../utils.h"
#include "../../tfhe/circuit_bootstrap.h"
#include "../../tfhe/cmux.h"
#include "../../tfhe/gadget.h"
#include "../../tfhe/hom_trace.h"
#include "../../tfhe/lwe.h"
#include "../../tfhe/mv_fbs.h"
#include "../../tfhe/fusepirc_selector.h"
#include "../../tfhe/raw_external_product.h"
#include "../../tfhe/raw_cmux.h"
#include "../../tfhe/raw_ntt.h"
#include "../../tfhe/raw_rlwe_prime.h"
#include "../../tfhe/raw_rlwe.h"
#include "../../tfhe/rgsw_layout.h"
#include "../../tfhe/scheme_switch.h"
#include "seal/seal.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <future>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <unordered_map>
#include <vector>

using namespace seal;
using namespace std;

namespace {
    constexpr const char *BOOTSTRAP_NOT_IMPLEMENTED = "secure circuit bootstrapping is not implemented yet";
    constexpr uint32_t CB_PARAMS_MAGIC = 0x4F584350;
    constexpr uint32_t CB_CLIENT_SECRET_MAGIC = 0x4F584353;
    constexpr uint32_t CB_EVAL_KEY_MAGIC = 0x4F584345;
    constexpr uint32_t RAW_MATRIX_MAGIC = 0x4F584D52;
    constexpr uint32_t RAW_RESPONSE_MAGIC = 0x4F585452;
    constexpr uint32_t FUSE_PIR_C_PAYLOAD_ELEMENT_BIT_LENGTH = 16;
    constexpr bool FUSE_PIR_C_PERF_LOG = false;
    struct FusePirCRawEncodedMatrix;
    static mutex g_eval_key_mutex;
    static unordered_map<uint64_t, shared_ptr<fusepirc::CachedCircuitBootstrapEvaluationKey>> g_eval_key_registry;
    static atomic<uint64_t> g_next_eval_key_handle{1};
    static mutex g_raw_matrix_mutex;
    static unordered_map<uint64_t, shared_ptr<FusePirCRawEncodedMatrix>> g_raw_matrix_registry;
    static atomic<uint64_t> g_next_raw_matrix_handle{1};
    static mutex g_perf_log_mutex;

    using Clock = chrono::steady_clock;

    uint64_t elapsed_ms(const Clock::time_point &start) {
        return static_cast<uint64_t>(chrono::duration_cast<chrono::milliseconds>(Clock::now() - start).count());
    }

    void perf_log(const string &message) {
        if (FUSE_PIR_C_PERF_LOG) {
            lock_guard<mutex> lock(g_perf_log_mutex);
            cerr << "[FusePIR-C-PERF] " << message << endl;
        }
    }

    vector<int> jint_array_to_vector(JNIEnv *env, jintArray array) {
        jsize length = env->GetArrayLength(array);
        jint *elements = env->GetIntArrayElements(array, nullptr);
        vector<int> result(elements, elements + length);
        env->ReleaseIntArrayElements(array, elements, JNI_ABORT);
        return result;
    }

    vector<uint8_t> jbyte_array_to_vector(JNIEnv *env, jbyteArray array) {
        jsize length = env->GetArrayLength(array);
        jbyte *data = env->GetByteArrayElements(array, nullptr);
        vector<uint8_t> result(static_cast<size_t>(length));
        for (jsize i = 0; i < length; i++) {
            result[static_cast<size_t>(i)] = static_cast<uint8_t>(data[i]);
        }
        env->ReleaseByteArrayElements(array, data, JNI_ABORT);
        return result;
    }

    jbyteArray vector_to_jbyte_array(JNIEnv *env, const vector<uint8_t> &data) {
        jbyteArray result = env->NewByteArray(static_cast<jsize>(data.size()));
        env->SetByteArrayRegion(result, 0, static_cast<jsize>(data.size()),
            reinterpret_cast<const jbyte *>(data.data()));
        return result;
    }

    void throw_runtime(JNIEnv *env, const char *message) {
        jclass exception = env->FindClass("java/lang/RuntimeException");
        if (exception != nullptr) {
            env->ThrowNew(exception, message);
        }
    }

    void throw_unsupported(JNIEnv *env, const char *message) {
        jclass exception = env->FindClass("java/lang/UnsupportedOperationException");
        if (exception != nullptr) {
            env->ThrowNew(exception, message);
        }
    }

    jobject new_array_list(JNIEnv *env) {
        jclass list_cls = env->FindClass("java/util/ArrayList");
        jmethodID list_init = env->GetMethodID(list_cls, "<init>", "()V");
        jobject list = env->NewObject(list_cls, list_init);
        env->DeleteLocalRef(list_cls);
        return list;
    }

    void list_add(JNIEnv *env, jobject list, jobject item) {
        jclass list_cls = env->FindClass("java/util/List");
        jmethodID add_method = env->GetMethodID(list_cls, "add", "(Ljava/lang/Object;)Z");
        env->CallBooleanMethod(list, add_method, item);
        env->DeleteLocalRef(list_cls);
    }

    jint call_int_getter(JNIEnv *env, jobject object, const char *name) {
        jclass cls = env->GetObjectClass(object);
        jmethodID method = env->GetMethodID(cls, name, "()I");
        jint value = env->CallIntMethod(object, method);
        env->DeleteLocalRef(cls);
        return value;
    }

    jlong call_long_getter(JNIEnv *env, jobject object, const char *name) {
        jclass cls = env->GetObjectClass(object);
        jmethodID method = env->GetMethodID(cls, name, "()J");
        jlong value = env->CallLongMethod(object, method);
        env->DeleteLocalRef(cls);
        return value;
    }

    jdouble call_double_getter(JNIEnv *env, jobject object, const char *name) {
        jclass cls = env->GetObjectClass(object);
        jmethodID method = env->GetMethodID(cls, name, "()D");
        jdouble value = env->CallDoubleMethod(object, method);
        env->DeleteLocalRef(cls);
        return value;
    }

    fusepirc::LweParams read_lwe_params(JNIEnv *env, jobject lwe_params) {
        fusepirc::LweParams params{};
        params.n = static_cast<uint32_t>(call_int_getter(env, lwe_params, "getDimension"));
        params.q = static_cast<uint64_t>(call_long_getter(env, lwe_params, "getModulus"));
        params.sigma = static_cast<double>(call_double_getter(env, lwe_params, "getSigma"));
        params.delta = static_cast<uint64_t>(call_long_getter(env, lwe_params, "getDelta"));
        if (params.delta != params.q / 2) {
            throw invalid_argument("FUSE_PIR_C LWE params must use delta = q / 2");
        }
        return params;
    }

    fusepirc::CircuitBootstrapParams read_circuit_bootstrap_params(JNIEnv *env, jobject bootstrap_params) {
        fusepirc::CircuitBootstrapParams params{};
        params.rgswLayout.gadgetLength = static_cast<uint32_t>(call_int_getter(env, bootstrap_params, "getGadgetLength"));
        params.rgswLayout.gadgetBase = static_cast<uint64_t>(call_long_getter(env, bootstrap_params, "getGadgetBase"));
        params.rgswLayout.componentOrder = fusepirc::ComponentOrder::BODY_FIRST;
        return params;
    }

    vector<int> jint_array_to_int_vector(JNIEnv *env, jintArray array) {
        jsize length = env->GetArrayLength(array);
        jint *elements = env->GetIntArrayElements(array, nullptr);
        vector<int> result(static_cast<size_t>(length));
        for (jsize i = 0; i < length; i++) {
            result[static_cast<size_t>(i)] = static_cast<int>(elements[i]);
        }
        env->ReleaseIntArrayElements(array, elements, JNI_ABORT);
        return result;
    }

    uint32_t ceil_log2(uint32_t n) {
        uint32_t log = 0;
        uint32_t pow = 1;
        while (pow < n) {
            pow <<= 1;
            log++;
        }
        return log;
    }

    Plaintext constant_plaintext(uint64_t value) {
        Plaintext plain(1);
        plain[0] = value;
        return plain;
    }

    uint64_t decrypt_constant_coeff(const Ciphertext &ciphertext, const SecretKey &secret_key,
                                    const SEALContext &context) {
        Ciphertext ct = ciphertext;
        Evaluator evaluator(context);
        if (ct.is_ntt_form()) {
            evaluator.transform_from_ntt_inplace(ct);
        }
        Decryptor decryptor(context, secret_key);
        Plaintext plain;
        decryptor.decrypt(ct, plain);
        return plain.coeff_count() == 0 ? 0 : plain[0];
    }

    uint64_t centered_distance(uint64_t value, uint64_t target, uint64_t modulus) {
        uint64_t forward = value >= target ? value - target : static_cast<uint64_t>(static_cast<__uint128_t>(value) + modulus - target);
        uint64_t backward = target >= value ? target - value : static_cast<uint64_t>(static_cast<__uint128_t>(target) + modulus - value);
        return min(forward, backward);
    }

    uint64_t fusepirc_payload_domain_size() {
        return UINT64_C(1) << FUSE_PIR_C_PAYLOAD_ELEMENT_BIT_LENGTH;
    }

    uint64_t fusepirc_payload_scale(uint64_t modulus) {
        uint64_t scale = modulus / fusepirc_payload_domain_size();
        return scale == 0 ? 1 : scale;
    }

    uint64_t encode_payload_to_raw_torus(uint64_t value, uint64_t modulus) {
        uint64_t payload = value % fusepirc_payload_domain_size();
        return static_cast<uint64_t>((static_cast<__uint128_t>(payload) * fusepirc_payload_scale(modulus)) % modulus);
    }

    uint64_t decode_payload_from_raw_torus(uint64_t coeff, uint64_t modulus) {
        uint64_t scale = fusepirc_payload_scale(modulus);
        uint64_t payload_mod = fusepirc_payload_domain_size();
        uint64_t rounded = static_cast<uint64_t>((static_cast<__uint128_t>(coeff) + scale / 2) / scale);
        return rounded % payload_mod;
    }

    fusepirc::MvFbsParams small_mv_fbs_params() {
        fusepirc::LweParams lwe_params{3, 128, 0.1, 64};
        // Primitive correctness parameter only; this is not claimed as a 128-bit security parameter.
        // Wang HomTrace trace-inverse scaling requires gcd(N,Q)=1, so Q is an odd prime.
        fusepirc::RawRlweParams rlwe_params{16, 65537, 17, false, {}};
        fusepirc::GadgetParams gadget_params{256, 8, 3, 65537, true};
        return fusepirc::MvFbsParams{
            lwe_params,
            rlwe_params,
            gadget_params,
            3,
            16,
            65537,
            128,
            2,
            32,
            true
        };
    }

    fusepirc::RawExternalProductParams small_raw_ep_params() {
        fusepirc::MvFbsParams params = small_mv_fbs_params();
        return fusepirc::RawExternalProductParams{
            params.rlweParams,
            params.gadgetParams,
            fusepirc::RgswLayout{
                params.gadgetParams.length,
                params.gadgetParams.base,
                fusepirc::ComponentOrder::BODY_FIRST
            }
        };
    }

    fusepirc::SchemeSwitchParams small_scheme_switch_params() {
        fusepirc::MvFbsParams mv_params = small_mv_fbs_params();
        fusepirc::RawExternalProductParams ep_params = small_raw_ep_params();
        return fusepirc::SchemeSwitchParams{
            mv_params.rlweParams,
            mv_params.rlweParams,
            mv_params.gadgetParams,
            ep_params.layout,
            mv_params.gadgetParams.length,
            mv_params.gadgetParams.base,
            mv_params.modulus,
            mv_params.degree,
            true
        };
    }

    fusepirc::CircuitBootstrapParams small_circuit_bootstrap_params() {
        fusepirc::MvFbsParams mv_params = small_mv_fbs_params();
        fusepirc::RawExternalProductParams ep_params = small_raw_ep_params();
        return fusepirc::make_circuit_bootstrap_params(
            mv_params.lweParams, mv_params.rlweParams, mv_params.gadgetParams, ep_params.layout
        );
    }

    fusepirc::CircuitBootstrapParams cmux_128_candidate_circuit_bootstrap_params() {
        fusepirc::LweParams lwe_params{571, 1024, 3.2, 512};
        fusepirc::RawRlweParams rlwe_params{2048, 18014398509404161ULL, 54, false, {}};
        fusepirc::GadgetParams gadget_params{
            64, 6, 5, 18014398509404161ULL, true,
            fusepirc::GadgetParams::ScaleMode::TORUS_APPROX_HIGH
        };
        fusepirc::RgswLayout layout{5, 64, fusepirc::ComponentOrder::BODY_FIRST};
        return fusepirc::make_circuit_bootstrap_params(lwe_params, rlwe_params, gadget_params, layout);
    }

    bool poly_close(const fusepirc::TorusPoly &actual, const fusepirc::TorusPoly &expected, uint64_t tolerance) {
        if (actual.degree != expected.degree || actual.modulus != expected.modulus) {
            return false;
        }
        for (uint32_t i = 0; i < actual.degree; i++) {
            if (centered_distance(actual.coeffs[i], expected.coeffs[i], actual.modulus) > tolerance) {
                return false;
            }
        }
        return true;
    }

    fusepirc::TorusPoly negacyclic_mul_poly_for_check(const fusepirc::TorusPoly &poly_a, const fusepirc::TorusPoly &poly_b) {
        fusepirc::validate_same_ring(poly_a, poly_b);
        fusepirc::TorusPoly out = fusepirc::zero_poly(poly_a.degree, poly_a.modulus);
        uint64_t two_degree = static_cast<uint64_t>(2) * poly_a.degree;
        for (uint32_t i = 0; i < poly_a.degree; i++) {
            for (uint32_t j = 0; j < poly_b.degree; j++) {
                uint64_t mapped = (static_cast<uint64_t>(i) + j) % two_degree;
                uint64_t product = static_cast<uint64_t>(
                    (static_cast<__uint128_t>(poly_a.coeffs[i]) * poly_b.coeffs[j]) % poly_a.modulus
                );
                if (mapped >= poly_a.degree) {
                    mapped -= poly_a.degree;
                    product = product == 0 ? 0 : poly_a.modulus - product;
                }
                out.coeffs[static_cast<uint32_t>(mapped)] = static_cast<uint64_t>(
                    (static_cast<__uint128_t>(out.coeffs[static_cast<uint32_t>(mapped)]) + product) % poly_a.modulus
                );
            }
        }
        return out;
    }

    uint64_t pow_mod_for_check(uint64_t base, uint32_t exponent, uint64_t modulus) {
        uint64_t result = 1 % modulus;
        for (uint32_t i = 0; i < exponent; i++) {
            result = static_cast<uint64_t>((static_cast<__uint128_t>(result) * base) % modulus);
        }
        return result;
    }

    vector<fusepirc::RawRlweCipher> make_traced_digits_for_bit(
        uint64_t bit, const fusepirc::RawRlweSecretKey &sk, const fusepirc::SchemeSwitchParams &params) {
        vector<fusepirc::RawRlweCipher> digits;
        digits.reserve(params.gadgetLength);
        for (uint32_t j = 0; j < params.gadgetLength; j++) {
            uint64_t gadget = pow_mod_for_check(params.gadgetBase, j, params.modulus);
            fusepirc::TorusPoly message = fusepirc::constant_poly(
                static_cast<uint64_t>((static_cast<__uint128_t>(gadget) * bit) % params.modulus),
                params.degree, params.modulus
            );
            digits.push_back(fusepirc::raw_rlwe_encrypt_poly(message, sk, params.inputParams, 0.1));
        }
        return digits;
    }

    vector<fusepirc::RawRgswCipher> encrypt_index_bits_to_rgsw_for_selector_check(
        uint32_t index, uint32_t bound, const fusepirc::CircuitBootstrapClientSecretState &client_secret,
        const fusepirc::CircuitBootstrapEvaluationKey &evaluation_key, const fusepirc::CircuitBootstrapParams &cb_params,
        uint8_t domain_separator) {
        uint32_t bit_num = ceil_log2(bound);
        vector<uint8_t> seed = fusepirc::make_random_lwe_seed();
        vector<fusepirc::RawRgswCipher> rgsw_bits;
        rgsw_bits.reserve(bit_num);
        for (uint32_t j = 0; j < bit_num; j++) {
            uint64_t bit = (index >> j) & 1U;
            fusepirc::LweCipher lwe_bit = fusepirc::lwe_encrypt_bit(
                bit, client_secret.lweSk, cb_params.lweParams, seed,
                fusepirc::make_lwe_domain(domain_separator, fusepirc::SelectorType::COL, j)
            );
            rgsw_bits.push_back(fusepirc::secure_lwe_to_rgsw(lwe_bit, evaluation_key, cb_params));
        }
        return rgsw_bits;
    }

    pair<fusepirc::CircuitBootstrapClientSecretState, fusepirc::CircuitBootstrapEvaluationKey> selector_check_keys(
        const fusepirc::CircuitBootstrapParams &params) {
        auto total_start = Clock::now();
        fusepirc::CircuitBootstrapClientSecretState client_secret;
        auto step_start = Clock::now();
        client_secret.lweSk = fusepirc::binary_lwe_keygen(params.lweParams);
        client_secret.rlweSk = fusepirc::raw_rlwe_keygen(params.rlweParams);
        perf_log("setup.keygen.secret_ms=" + to_string(elapsed_ms(step_start))
            + ", lweN=" + to_string(params.lweParams.n)
            + ", rawRlweN=" + to_string(params.degree));
        step_start = Clock::now();
        fusepirc::MvFbsKey mv_key = fusepirc::generate_mv_fbs_key(
            client_secret.lweSk, client_secret.rlweSk, params.mvFbsParams, params.mvFbsExternalProductParams
        );
        perf_log("setup.keygen.mv_fbs_key_ms=" + to_string(elapsed_ms(step_start)));
        double key_switch_sigma = params.gadgetParams.scaleMode == fusepirc::GadgetParams::ScaleMode::TORUS_APPROX_HIGH
            ? 0.001 : params.lweParams.sigma;
        step_start = Clock::now();
        fusepirc::HomTraceKey trace_key = fusepirc::generate_hom_trace_key(
            client_secret.rlweSk, params.homTraceParams, key_switch_sigma
        );
        perf_log("setup.keygen.hom_trace_key_ms=" + to_string(elapsed_ms(step_start)));
        step_start = Clock::now();
        fusepirc::SchemeSwitchKey switch_key = fusepirc::generate_scheme_switch_key(
            client_secret.rlweSk, params.schemeSwitchParams, key_switch_sigma
        );
        perf_log("setup.keygen.scheme_switch_key_ms=" + to_string(elapsed_ms(step_start)));
        perf_log("setup.keygen.total_ms=" + to_string(elapsed_ms(total_start)));
        return {client_secret, fusepirc::CircuitBootstrapEvaluationKey{mv_key, trace_key, switch_key}};
    }

    struct FusePirCRawEncodedMatrix {
        uint32_t rowNum;
        uint32_t colNum;
        uint32_t rowStride;
        uint32_t payloadBlockNum;
        uint32_t blocksPerPackedMatrix;
        uint32_t packedMatrixGroupNum;
        uint32_t bffHashNum;
        vector<vector<fusepirc::TorusPoly>> columns;
        vector<vector<vector<fusepirc::TorusPoly>>> decomposedColumns;
    };

    struct FusePirCRawResponse {
        uint32_t payloadBlockNum;
        uint32_t blocksPerPackedMatrix;
        uint32_t packedMatrixGroupNum;
        vector<fusepirc::RawRlweCipher> blocks;
    };

    struct RecoveredFusePirCQueryBits {
        array<vector<fusepirc::LweCipher>, 3> colBits;
        array<vector<fusepirc::LweCipher>, 3> rowBits;
    };

    struct HashReplyResult {
        fusepirc::RawRlweCipher selectedRow;
        uint64_t colSecureMs;
        uint64_t rowSecureMs;
        uint64_t selectorMs;
        uint64_t columnMs;
        uint64_t rowRgswNttCacheMs;
        uint64_t rowBlindRotateMs;
        uint64_t convertedBitCount;
    };

    struct PrecomputedHashMaterial {
        vector<fusepirc::CachedRawRgswCipherNtt> colRgswBitsNtt;
        vector<fusepirc::CachedRawRgswCipherNtt> rowRgswBitsNtt;
        uint64_t colSecureMs = 0;
        uint64_t rowSecureMs = 0;
        uint64_t selectorMs = 0;
        uint64_t rowRgswNttCacheMs = 0;
        uint64_t convertedBitCount = 0;
    };

    void put_u32_local(vector<uint8_t> &out, uint32_t value) {
        out.push_back(static_cast<uint8_t>(value >> 24));
        out.push_back(static_cast<uint8_t>(value >> 16));
        out.push_back(static_cast<uint8_t>(value >> 8));
        out.push_back(static_cast<uint8_t>(value));
    }

    void put_u64_local(vector<uint8_t> &out, uint64_t value) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            out.push_back(static_cast<uint8_t>(value >> shift));
        }
    }

    uint32_t read_u32_local(const vector<uint8_t> &in, size_t &offset) {
        if (offset + sizeof(uint32_t) > in.size()) {
            throw invalid_argument("truncated raw response uint32");
        }
        uint32_t value = 0;
        for (int i = 0; i < 4; i++) {
            value = (value << 8) | in[offset++];
        }
        return value;
    }

    uint64_t read_u64_local(const vector<uint8_t> &in, size_t &offset) {
        if (offset + sizeof(uint64_t) > in.size()) {
            throw invalid_argument("truncated raw response uint64");
        }
        uint64_t value = 0;
        for (int i = 0; i < 8; i++) {
            value = (value << 8) | in[offset++];
        }
        return value;
    }

    uint32_t b_element_byte_length(uint64_t q) {
        if (q <= 1) {
            throw invalid_argument("LWE modulus must be greater than one");
        }
        uint32_t bit_length = 64 - static_cast<uint32_t>(__builtin_clzll(q - 1));
        return (bit_length + 7) / 8;
    }

    void put_double_local(vector<uint8_t> &out, double value) {
        uint64_t bits;
        static_assert(sizeof(bits) == sizeof(value), "double must be 64 bits");
        memcpy(&bits, &value, sizeof(bits));
        put_u64_local(out, bits);
    }

    double read_double_local(const vector<uint8_t> &in, size_t &offset) {
        uint64_t bits = read_u64_local(in, offset);
        double value;
        memcpy(&value, &bits, sizeof(value));
        return value;
    }

    uint32_t bit_length_u64(uint64_t value) {
        if (value == 0) {
            return 0;
        }
        return 64 - static_cast<uint32_t>(__builtin_clzll(value));
    }

    void serialize_torus_poly_into(vector<uint8_t> &out, const fusepirc::TorusPoly &poly) {
        fusepirc::validate_torus_poly(poly);
        put_u32_local(out, poly.degree);
        put_u64_local(out, poly.modulus);
        for (uint64_t coeff : poly.coeffs) {
            put_u64_local(out, coeff);
        }
    }

    fusepirc::TorusPoly deserialize_torus_poly_from(const vector<uint8_t> &in, size_t &offset) {
        uint32_t degree = read_u32_local(in, offset);
        uint64_t modulus = read_u64_local(in, offset);
        fusepirc::TorusPoly poly = fusepirc::zero_poly(degree, modulus);
        for (uint32_t i = 0; i < degree; i++) {
            poly.coeffs[i] = read_u64_local(in, offset);
            if (poly.coeffs[i] >= modulus) {
                throw invalid_argument("serialized TorusPoly coefficient out of range");
            }
        }
        return poly;
    }

    void serialize_raw_rlwe_into(vector<uint8_t> &out, const fusepirc::RawRlweCipher &ct) {
        if (ct.isNttForm) {
            throw invalid_argument("cannot serialize NTT-form RawRLWE");
        }
        serialize_torus_poly_into(out, ct.a);
        serialize_torus_poly_into(out, ct.b);
    }

    fusepirc::RawRlweCipher deserialize_raw_rlwe_from(const vector<uint8_t> &in, size_t &offset) {
        fusepirc::TorusPoly a = deserialize_torus_poly_from(in, offset);
        fusepirc::TorusPoly b = deserialize_torus_poly_from(in, offset);
        if (a.degree != b.degree || a.modulus != b.modulus) {
            throw invalid_argument("serialized RawRLWE ring mismatch");
        }
        fusepirc::RawRlweParams params{a.degree, a.modulus, bit_length_u64(a.modulus), false, {}};
        return fusepirc::RawRlweCipher{a, b, params, false, 0};
    }

    void serialize_raw_rgsw_into(vector<uint8_t> &out, const fusepirc::RawRgswCipher &rgsw) {
        put_u32_local(out, rgsw.layout.gadgetLength);
        put_u64_local(out, rgsw.layout.gadgetBase);
        put_u32_local(out, static_cast<uint32_t>(rgsw.layout.componentOrder));
        put_u32_local(out, rgsw.params.degree);
        put_u64_local(out, rgsw.params.modulus);
        put_u32_local(out, static_cast<uint32_t>(rgsw.components.size()));
        for (const fusepirc::RawRlweCipher &component : rgsw.components) {
            serialize_raw_rlwe_into(out, component);
        }
    }

    fusepirc::RawRgswCipher deserialize_raw_rgsw_from(const vector<uint8_t> &in, size_t &offset) {
        fusepirc::RgswLayout layout;
        layout.gadgetLength = read_u32_local(in, offset);
        layout.gadgetBase = read_u64_local(in, offset);
        uint32_t order = read_u32_local(in, offset);
        if (order != static_cast<uint32_t>(fusepirc::ComponentOrder::BODY_FIRST)) {
            throw invalid_argument("serialized RawRGSW unsupported layout order");
        }
        layout.componentOrder = fusepirc::ComponentOrder::BODY_FIRST;
        uint32_t degree = read_u32_local(in, offset);
        uint64_t modulus = read_u64_local(in, offset);
        fusepirc::RawRlweParams params{degree, modulus, bit_length_u64(modulus), false, {}};
        uint32_t component_count = read_u32_local(in, offset);
        fusepirc::RawRgswCipher rgsw{{}, layout, params};
        rgsw.components.reserve(component_count);
        for (uint32_t i = 0; i < component_count; i++) {
            fusepirc::RawRlweCipher component = deserialize_raw_rlwe_from(in, offset);
            if (component.params.degree != params.degree || component.params.modulus != params.modulus) {
                throw invalid_argument("serialized RawRGSW component params mismatch");
            }
            rgsw.components.push_back(component);
        }
        return rgsw;
    }

    vector<uint8_t> serialize_circuit_bootstrap_params(const fusepirc::CircuitBootstrapParams &params) {
        vector<uint8_t> out;
        put_u32_local(out, CB_PARAMS_MAGIC);
        put_u32_local(out, params.lweParams.n);
        put_u64_local(out, params.lweParams.q);
        put_double_local(out, params.lweParams.sigma);
        put_u64_local(out, params.lweParams.delta);
        put_u32_local(out, params.rlweParams.degree);
        put_u64_local(out, params.rlweParams.modulus);
        put_u32_local(out, params.gadgetParams.baseBitLength);
        put_u64_local(out, params.gadgetParams.base);
        put_u32_local(out, params.gadgetParams.length);
        put_u32_local(out, static_cast<uint32_t>(params.gadgetParams.scaleMode));
        put_u64_local(out, params.rgswLayout.gadgetBase);
        put_u32_local(out, params.rgswLayout.gadgetLength);
        put_u32_local(out, static_cast<uint32_t>(params.rgswLayout.componentOrder));
        return out;
    }

    fusepirc::CircuitBootstrapParams deserialize_circuit_bootstrap_params(const vector<uint8_t> &encoded) {
        size_t offset = 0;
        if (read_u32_local(encoded, offset) != CB_PARAMS_MAGIC) {
            throw invalid_argument("invalid serialized circuit bootstrap params");
        }
        fusepirc::LweParams lwe_params{
            read_u32_local(encoded, offset),
            read_u64_local(encoded, offset),
            read_double_local(encoded, offset),
            0
        };
        lwe_params.delta = read_u64_local(encoded, offset);
        uint32_t degree = read_u32_local(encoded, offset);
        uint64_t modulus = read_u64_local(encoded, offset);
        fusepirc::RawRlweParams rlwe_params{degree, modulus, bit_length_u64(modulus), false, {}};
        uint32_t base_bit_length = read_u32_local(encoded, offset);
        uint64_t gadget_base = read_u64_local(encoded, offset);
        uint32_t gadget_length = read_u32_local(encoded, offset);
        uint32_t scale_mode_value = read_u32_local(encoded, offset);
        if (scale_mode_value > static_cast<uint32_t>(fusepirc::GadgetParams::ScaleMode::TORUS_APPROX_HIGH)) {
            throw invalid_argument("serialized circuit bootstrap gadget scale mode mismatch");
        }
        fusepirc::GadgetParams gadget_params{
            gadget_base, base_bit_length, gadget_length, rlwe_params.modulus, true,
            static_cast<fusepirc::GadgetParams::ScaleMode>(scale_mode_value)
        };
        uint64_t layout_base = read_u64_local(encoded, offset);
        uint32_t layout_length = read_u32_local(encoded, offset);
        uint32_t order = read_u32_local(encoded, offset);
        if (layout_base != gadget_base || layout_length != gadget_length
            || order != static_cast<uint32_t>(fusepirc::ComponentOrder::BODY_FIRST)) {
            throw invalid_argument("serialized circuit bootstrap layout mismatch");
        }
        if (offset != encoded.size()) {
            throw invalid_argument("extra bytes in circuit bootstrap params");
        }
        fusepirc::RgswLayout layout{layout_length, layout_base, fusepirc::ComponentOrder::BODY_FIRST};
        return fusepirc::make_circuit_bootstrap_params(lwe_params, rlwe_params, gadget_params, layout);
    }

    vector<uint8_t> serialize_circuit_bootstrap_client_secret(
        const fusepirc::CircuitBootstrapClientSecretState &state) {
        vector<uint8_t> out;
        put_u32_local(out, CB_CLIENT_SECRET_MAGIC);
        put_u32_local(out, static_cast<uint32_t>(state.lweSk.s.size()));
        for (uint64_t bit : state.lweSk.s) {
            put_u64_local(out, bit);
        }
        serialize_torus_poly_into(out, state.rlweSk.s);
        return out;
    }

    fusepirc::CircuitBootstrapClientSecretState deserialize_circuit_bootstrap_client_secret(
        const vector<uint8_t> &encoded) {
        size_t offset = 0;
        if (read_u32_local(encoded, offset) != CB_CLIENT_SECRET_MAGIC) {
            throw invalid_argument("invalid serialized client secret");
        }
        fusepirc::CircuitBootstrapClientSecretState state;
        uint32_t lwe_n = read_u32_local(encoded, offset);
        state.lweSk.s.resize(lwe_n);
        for (uint32_t i = 0; i < lwe_n; i++) {
            state.lweSk.s[i] = read_u64_local(encoded, offset);
        }
        state.rlweSk.s = deserialize_torus_poly_from(encoded, offset);
        if (offset != encoded.size()) {
            throw invalid_argument("extra bytes in client secret");
        }
        return state;
    }

    vector<uint8_t> serialize_circuit_bootstrap_evaluation_key(
        const fusepirc::CircuitBootstrapEvaluationKey &key) {
        vector<uint8_t> out;
        put_u32_local(out, CB_EVAL_KEY_MAGIC);
        put_u32_local(out, static_cast<uint32_t>(key.mvFbsKey.bootstrappingKey.size()));
        for (const fusepirc::RawRgswCipher &rgsw : key.mvFbsKey.bootstrappingKey) {
            serialize_raw_rgsw_into(out, rgsw);
        }
        put_u32_local(out, static_cast<uint32_t>(key.homTraceKey.automorphismKeys.size()));
        for (const fusepirc::RawAutomorphismKey &aut_key : key.homTraceKey.automorphismKeys) {
            put_u32_local(out, aut_key.automorphismExponent);
            put_u32_local(out, static_cast<uint32_t>(aut_key.keySwitchComponents.size()));
            for (const fusepirc::RawRlweCipher &component : aut_key.keySwitchComponents) {
                serialize_raw_rlwe_into(out, component);
            }
        }
        serialize_raw_rlwe_into(out, key.schemeSwitchKey.encryptedSkSquare);
        put_u32_local(out, static_cast<uint32_t>(key.schemeSwitchKey.keySwitchComponents.size()));
        for (const fusepirc::RawRlweCipher &component : key.schemeSwitchKey.keySwitchComponents) {
            serialize_raw_rlwe_into(out, component);
        }
        return out;
    }

    fusepirc::CircuitBootstrapEvaluationKey deserialize_circuit_bootstrap_evaluation_key(
        const vector<uint8_t> &encoded, const fusepirc::CircuitBootstrapParams &params) {
        size_t offset = 0;
        if (read_u32_local(encoded, offset) != CB_EVAL_KEY_MAGIC) {
            throw invalid_argument("invalid serialized evaluation key");
        }
        fusepirc::CircuitBootstrapEvaluationKey key;
        uint32_t mv_key_size = read_u32_local(encoded, offset);
        key.mvFbsKey.bootstrappingKey.reserve(mv_key_size);
        for (uint32_t i = 0; i < mv_key_size; i++) {
            key.mvFbsKey.bootstrappingKey.push_back(deserialize_raw_rgsw_from(encoded, offset));
        }
        fusepirc::GadgetParams hom_trace_key_switch_gadget = params.homTraceKeySwitchGadgetParams;
        key.homTraceKey.params = params.rlweParams;
        key.homTraceKey.gadgetParams = hom_trace_key_switch_gadget;
        uint32_t aut_key_size = read_u32_local(encoded, offset);
        key.homTraceKey.automorphismKeys.reserve(aut_key_size);
        for (uint32_t i = 0; i < aut_key_size; i++) {
            fusepirc::RawAutomorphismKey aut_key;
            aut_key.automorphismExponent = read_u32_local(encoded, offset);
            aut_key.params = params.rlweParams;
            aut_key.gadgetParams = hom_trace_key_switch_gadget;
            uint32_t component_count = read_u32_local(encoded, offset);
            aut_key.keySwitchComponents.reserve(component_count);
            for (uint32_t j = 0; j < component_count; j++) {
                aut_key.keySwitchComponents.push_back(deserialize_raw_rlwe_from(encoded, offset));
            }
            key.homTraceKey.automorphismKeys.push_back(aut_key);
        }
        key.schemeSwitchKey.params = params.rlweParams;
        key.schemeSwitchKey.gadgetParams = params.outputGadgetParams;
        key.schemeSwitchKey.rgswLayout = params.outputRgswLayout;
        key.schemeSwitchKey.encryptedSkSquare = deserialize_raw_rlwe_from(encoded, offset);
        uint32_t switch_component_count = read_u32_local(encoded, offset);
        key.schemeSwitchKey.keySwitchComponents.reserve(switch_component_count);
        for (uint32_t i = 0; i < switch_component_count; i++) {
            key.schemeSwitchKey.keySwitchComponents.push_back(deserialize_raw_rlwe_from(encoded, offset));
        }
        if (offset != encoded.size()) {
            throw invalid_argument("extra bytes in evaluation key");
        }
        if (key.mvFbsKey.bootstrappingKey.size() != params.lweParams.n
            || key.homTraceKey.automorphismKeys.size() != params.homTraceParams.automorphismExponents.size()) {
            throw invalid_argument("serialized evaluation key size mismatch");
        }
        return key;
    }

    uint64_t register_evaluation_key(shared_ptr<fusepirc::CachedCircuitBootstrapEvaluationKey> key) {
        if (!key) {
            throw invalid_argument("cannot register empty evaluation key");
        }
        uint64_t handle = g_next_eval_key_handle.fetch_add(1);
        if (handle == 0) {
            handle = g_next_eval_key_handle.fetch_add(1);
        }
        lock_guard<mutex> lock(g_eval_key_mutex);
        g_eval_key_registry.emplace(handle, std::move(key));
        return handle;
    }

    shared_ptr<fusepirc::CachedCircuitBootstrapEvaluationKey> get_evaluation_key(uint64_t handle) {
        if (handle == 0) {
            throw invalid_argument("invalid zero evaluation key handle");
        }
        lock_guard<mutex> lock(g_eval_key_mutex);
        auto it = g_eval_key_registry.find(handle);
        if (it == g_eval_key_registry.end()) {
            throw invalid_argument("unknown evaluation key handle");
        }
        return it->second;
    }

    void unregister_evaluation_key(uint64_t handle) {
        lock_guard<mutex> lock(g_eval_key_mutex);
        g_eval_key_registry.erase(handle);
    }

    uint64_t register_raw_matrix(shared_ptr<FusePirCRawEncodedMatrix> matrix) {
        if (!matrix) {
            throw invalid_argument("cannot register empty raw matrix");
        }
        uint64_t handle = g_next_raw_matrix_handle.fetch_add(1);
        if (handle == 0) {
            handle = g_next_raw_matrix_handle.fetch_add(1);
        }
        lock_guard<mutex> lock(g_raw_matrix_mutex);
        g_raw_matrix_registry.emplace(handle, std::move(matrix));
        return handle;
    }

    shared_ptr<FusePirCRawEncodedMatrix> get_raw_matrix(uint64_t handle) {
        if (handle == 0) {
            throw invalid_argument("invalid zero raw matrix handle");
        }
        lock_guard<mutex> lock(g_raw_matrix_mutex);
        auto it = g_raw_matrix_registry.find(handle);
        if (it == g_raw_matrix_registry.end()) {
            throw invalid_argument("unknown raw matrix handle");
        }
        return it->second;
    }

    void unregister_raw_matrix(uint64_t handle) {
        lock_guard<mutex> lock(g_raw_matrix_mutex);
        g_raw_matrix_registry.erase(handle);
    }

    vector<uint8_t> serialize_raw_rlwe_cipher_vector(
        const vector<fusepirc::RawRlweCipher> &response_blocks, uint32_t payload_block_num = 0,
        uint32_t blocks_per_packed_matrix = 1, uint32_t packed_matrix_group_num = 0) {
        vector<uint8_t> out;
        uint32_t response_cipher_count = static_cast<uint32_t>(response_blocks.size());
        if (payload_block_num == 0) {
            payload_block_num = response_cipher_count;
        }
        if (packed_matrix_group_num == 0) {
            packed_matrix_group_num = response_cipher_count;
        }
        if (blocks_per_packed_matrix == 0 || packed_matrix_group_num != response_cipher_count
            || packed_matrix_group_num
            != (payload_block_num + blocks_per_packed_matrix - 1) / blocks_per_packed_matrix) {
            throw invalid_argument("raw response packing metadata mismatch");
        }
        put_u32_local(out, RAW_RESPONSE_MAGIC);
        put_u32_local(out, response_cipher_count);
        put_u32_local(out, payload_block_num);
        put_u32_local(out, blocks_per_packed_matrix);
        put_u32_local(out, packed_matrix_group_num);
        if (response_blocks.empty()) {
            return out;
        }
        uint32_t degree = response_blocks[0].params.degree;
        uint64_t modulus = response_blocks[0].params.modulus;
        put_u32_local(out, degree);
        put_u64_local(out, modulus);
        for (const fusepirc::RawRlweCipher &ct : response_blocks) {
            if (ct.params.degree != degree || ct.params.modulus != modulus || ct.isNttForm) {
                throw invalid_argument("raw response serialization params mismatch");
            }
            for (uint64_t coeff : ct.a.coeffs) {
                put_u64_local(out, coeff);
            }
            for (uint64_t coeff : ct.b.coeffs) {
                put_u64_local(out, coeff);
            }
        }
        return out;
    }

    FusePirCRawResponse deserialize_raw_response(const vector<uint8_t> &encoded) {
        size_t offset = 0;
        uint32_t magic_or_count = read_u32_local(encoded, offset);
        FusePirCRawResponse response;
        uint32_t block_count;
        if (magic_or_count == RAW_RESPONSE_MAGIC) {
            block_count = read_u32_local(encoded, offset);
            response.payloadBlockNum = read_u32_local(encoded, offset);
            response.blocksPerPackedMatrix = read_u32_local(encoded, offset);
            response.packedMatrixGroupNum = read_u32_local(encoded, offset);
        } else {
            block_count = magic_or_count;
            response.payloadBlockNum = block_count;
            response.blocksPerPackedMatrix = 1;
            response.packedMatrixGroupNum = block_count;
        }
        if (response.blocksPerPackedMatrix == 0 || response.packedMatrixGroupNum != block_count
            || response.packedMatrixGroupNum
            != (response.payloadBlockNum + response.blocksPerPackedMatrix - 1) / response.blocksPerPackedMatrix) {
            throw invalid_argument("raw response metadata mismatch");
        }
        if (block_count == 0) {
            if (offset != encoded.size()) {
                throw invalid_argument("extra bytes in empty raw response");
            }
            return response;
        }
        uint32_t degree = read_u32_local(encoded, offset);
        uint64_t modulus = read_u64_local(encoded, offset);
        fusepirc::RawRlweParams params{degree, modulus, bit_length_u64(modulus), false, {}};
        response.blocks.reserve(block_count);
        for (uint32_t block = 0; block < block_count; block++) {
            fusepirc::TorusPoly a = fusepirc::zero_poly(degree, modulus);
            fusepirc::TorusPoly b = fusepirc::zero_poly(degree, modulus);
            for (uint32_t i = 0; i < degree; i++) {
                a.coeffs[i] = read_u64_local(encoded, offset);
                if (a.coeffs[i] >= modulus) {
                    throw invalid_argument("raw response a coefficient out of range");
                }
            }
            for (uint32_t i = 0; i < degree; i++) {
                b.coeffs[i] = read_u64_local(encoded, offset);
                if (b.coeffs[i] >= modulus) {
                    throw invalid_argument("raw response b coefficient out of range");
                }
            }
            response.blocks.push_back(fusepirc::RawRlweCipher{a, b, params, false, 0});
        }
        if (offset != encoded.size()) {
            throw invalid_argument("extra bytes in raw response");
        }
        return response;
    }

    vector<fusepirc::RawRlweCipher> deserialize_raw_rlwe_cipher_vector(const vector<uint8_t> &encoded) {
        return deserialize_raw_response(encoded).blocks;
    }

    RecoveredFusePirCQueryBits recover_lwe_bits_from_fusepirc_query(
        const fusepirc::CompressedLweBits &query, const fusepirc::CircuitBootstrapParams &cb_params,
        uint32_t row_num, uint32_t col_num) {
        if (query.bff_hash_num != 3) {
            throw invalid_argument("FUSE_PIR_C generateReply requires bffHashNum = 3");
        }
        uint32_t row_bit_num = ceil_log2(row_num);
        uint32_t col_bit_num = ceil_log2(col_num);
        if (query.row_bit_num != row_bit_num || query.col_bit_num != col_bit_num) {
            throw invalid_argument("FUSE_PIR_C compressed query bit metadata mismatch");
        }
        if (query.lwe_dimension != cb_params.lweParams.n || query.q != cb_params.lweParams.q) {
            throw invalid_argument("FUSE_PIR_C compressed query LWE params mismatch");
        }
        uint32_t expected_b_count = 3 * (row_bit_num + col_bit_num);
        if (query.b_array.size() != expected_b_count) {
            throw invalid_argument("FUSE_PIR_C compressed query bArray length mismatch");
        }
        RecoveredFusePirCQueryBits bits;
        size_t b_index = 0;
        for (uint32_t hash_position = 0; hash_position < 3; hash_position++) {
            bits.colBits[hash_position].reserve(col_bit_num);
            bits.rowBits[hash_position].reserve(row_bit_num);
            for (uint32_t bit_index = 0; bit_index < col_bit_num; bit_index++) {
                fusepirc::LweCipher cipher;
                cipher.a = fusepirc::prg_expand_lwe_a(query.seed, fusepirc::make_lwe_domain(
                    hash_position, fusepirc::SelectorType::COL, bit_index
                ), cb_params.lweParams.n, cb_params.lweParams.q);
                cipher.b = query.b_array[b_index++];
                bits.colBits[hash_position].push_back(std::move(cipher));
            }
            for (uint32_t bit_index = 0; bit_index < row_bit_num; bit_index++) {
                fusepirc::LweCipher cipher;
                cipher.a = fusepirc::prg_expand_lwe_a(query.seed, fusepirc::make_lwe_domain(
                    hash_position, fusepirc::SelectorType::ROW, bit_index
                ), cb_params.lweParams.n, cb_params.lweParams.q);
                cipher.b = query.b_array[b_index++];
                bits.rowBits[hash_position].push_back(std::move(cipher));
            }
        }
        return bits;
    }

    void validate_raw_encoded_matrix(
        const FusePirCRawEncodedMatrix &matrix, const fusepirc::RawRlweParams &rlwe_params) {
        if (matrix.bffHashNum != 3 || matrix.rowNum == 0 || matrix.colNum == 0 || matrix.payloadBlockNum == 0
            || matrix.blocksPerPackedMatrix == 0 || matrix.packedMatrixGroupNum == 0 || matrix.rowStride == 0) {
            throw invalid_argument("invalid FUSE_PIR_C raw encoded matrix metadata");
        }
        if (matrix.rowStride != matrix.blocksPerPackedMatrix) {
            throw invalid_argument("FUSE_PIR_C raw encoded matrix row stride / packing mismatch");
        }
        if (matrix.packedMatrixGroupNum
            != (matrix.payloadBlockNum + matrix.blocksPerPackedMatrix - 1) / matrix.blocksPerPackedMatrix) {
            throw invalid_argument("FUSE_PIR_C raw encoded matrix packed group count mismatch");
        }
        if (static_cast<uint64_t>(matrix.rowNum) * matrix.rowStride > rlwe_params.degree) {
            throw invalid_argument("FUSE_PIR_C raw encoded matrix rows exceed raw RLWE degree");
        }
        if (matrix.columns.size() != matrix.packedMatrixGroupNum) {
            throw invalid_argument("FUSE_PIR_C raw encoded matrix packed group dimension mismatch");
        }
        for (uint32_t g = 0; g < matrix.packedMatrixGroupNum; g++) {
            if (matrix.columns[g].size() != matrix.colNum) {
                throw invalid_argument("FUSE_PIR_C raw encoded matrix column dimension mismatch");
            }
            for (const fusepirc::TorusPoly &column : matrix.columns[g]) {
                fusepirc::validate_torus_poly(column);
                if (column.degree != rlwe_params.degree || column.modulus != rlwe_params.modulus) {
                    throw invalid_argument("FUSE_PIR_C raw encoded matrix column ring mismatch");
                }
            }
        }
    }

    void cache_raw_matrix_column_decomposition(
        FusePirCRawEncodedMatrix &matrix, const fusepirc::GadgetParams &gadget_params) {
        matrix.decomposedColumns.clear();
        matrix.decomposedColumns.resize(matrix.packedMatrixGroupNum);
        for (uint32_t g = 0; g < matrix.packedMatrixGroupNum; g++) {
            matrix.decomposedColumns[g].reserve(matrix.colNum);
            for (uint32_t c = 0; c < matrix.colNum; c++) {
                matrix.decomposedColumns[g].push_back(
                    fusepirc::gadget_decompose(matrix.columns[g][c], gadget_params)
                );
            }
        }
    }

    bool has_cached_raw_matrix_column_decomposition(const FusePirCRawEncodedMatrix &matrix) {
        if (matrix.decomposedColumns.size() != matrix.packedMatrixGroupNum) {
            return false;
        }
        for (uint32_t g = 0; g < matrix.packedMatrixGroupNum; g++) {
            if (matrix.decomposedColumns[g].size() != matrix.colNum) {
                return false;
            }
        }
        return true;
    }

    vector<uint8_t> serialize_raw_encoded_matrix(const FusePirCRawEncodedMatrix &matrix) {
        vector<uint8_t> out;
        put_u32_local(out, RAW_MATRIX_MAGIC);
        put_u32_local(out, matrix.rowNum);
        put_u32_local(out, matrix.colNum);
        put_u32_local(out, matrix.rowStride);
        put_u32_local(out, matrix.payloadBlockNum);
        put_u32_local(out, matrix.blocksPerPackedMatrix);
        put_u32_local(out, matrix.packedMatrixGroupNum);
        put_u32_local(out, matrix.bffHashNum);
        for (uint32_t g = 0; g < matrix.packedMatrixGroupNum; g++) {
            for (uint32_t c = 0; c < matrix.colNum; c++) {
                serialize_torus_poly_into(out, matrix.columns[g][c]);
            }
        }
        return out;
    }

    FusePirCRawEncodedMatrix deserialize_raw_encoded_matrix(
        const vector<uint8_t> &encoded, const fusepirc::RawRlweParams &rlwe_params) {
        size_t offset = 0;
        if (read_u32_local(encoded, offset) != RAW_MATRIX_MAGIC) {
            throw invalid_argument("invalid serialized raw FUSE_PIR_C matrix");
        }
        FusePirCRawEncodedMatrix matrix;
        matrix.rowNum = read_u32_local(encoded, offset);
        matrix.colNum = read_u32_local(encoded, offset);
        matrix.rowStride = read_u32_local(encoded, offset);
        matrix.payloadBlockNum = read_u32_local(encoded, offset);
        matrix.blocksPerPackedMatrix = read_u32_local(encoded, offset);
        matrix.packedMatrixGroupNum = read_u32_local(encoded, offset);
        matrix.bffHashNum = read_u32_local(encoded, offset);
        matrix.columns.resize(matrix.packedMatrixGroupNum);
        for (uint32_t g = 0; g < matrix.packedMatrixGroupNum; g++) {
            matrix.columns[g].reserve(matrix.colNum);
            for (uint32_t c = 0; c < matrix.colNum; c++) {
                matrix.columns[g].push_back(deserialize_torus_poly_from(encoded, offset));
            }
        }
        if (offset != encoded.size()) {
            throw invalid_argument("extra bytes in raw FUSE_PIR_C matrix");
        }
        validate_raw_encoded_matrix(matrix, rlwe_params);
        return matrix;
    }

    vector<fusepirc::RawRlweCipher> generate_fusepirc_raw_reply(
        const fusepirc::CompressedLweBits &query, const fusepirc::CachedCircuitBootstrapEvaluationKey &evaluation_key,
        const fusepirc::CircuitBootstrapParams &cb_params, const FusePirCRawEncodedMatrix &encoded_matrix) {
        // FUSE_PIR_C online query is seed + bArray + metadata only.
        // For each BFF hash position, the server recovers LWE row/column bits from the seed,
        // converts every bit with secure_lwe_to_rgsw and evaluates the equivalent Pirouette
        // column selection as a recursive CMUX tree,
        // and then applies raw row-to-zero BlindRotate. FUSE_PIR_C does not use the old RLWE column
        // query or the RawRLWE(X^col) monomial selector as the main path; setup evaluation keys
        // are not counted in online query size.
        auto total_start = Clock::now();
        auto step_start = Clock::now();
        validate_raw_encoded_matrix(encoded_matrix, cb_params.rlweParams);
        RecoveredFusePirCQueryBits query_bits = recover_lwe_bits_from_fusepirc_query(
            query, cb_params, encoded_matrix.rowNum, encoded_matrix.colNum
        );
        perf_log("generateReply.recover_lwe_bits_ms=" + to_string(elapsed_ms(step_start)));
        vector<fusepirc::RawRlweCipher> response_blocks;
        response_blocks.reserve(encoded_matrix.packedMatrixGroupNum);
        uint64_t total_secure_ms = 0;
        uint64_t total_selector_ms = 0;
        uint64_t total_column_ms = 0;
        uint64_t total_row_ms = 0;
        uint64_t total_row_rgsw_ntt_cache_ms = 0;
        uint64_t total_sum_ms = 0;
        uint64_t total_converted_bits = 0;
        fusepirc::RawNttParams ntt_params = fusepirc::get_cached_raw_ntt_params(
            cb_params.rlweParams.degree, cb_params.rlweParams.modulus
        );
        array<PrecomputedHashMaterial, 3> precomputed_hashes;
        for (uint32_t hash_position = 0; hash_position < 3; hash_position++) {
            vector<fusepirc::RawRgswCipher> col_rgsw_bits;
            uint64_t converted_bits = 0;
            if (!query_bits.colBits[hash_position].empty()) {
                auto hash_step_start = Clock::now();
                string col_prefix = "hash" + to_string(hash_position) + ".col";
                col_rgsw_bits = fusepirc::secure_lwe_bits_to_rgsw_batch_cached_ntt(
                    query_bits.colBits[hash_position], evaluation_key, cb_params, col_prefix.c_str()
                );
                precomputed_hashes[hash_position].colSecureMs = elapsed_ms(hash_step_start);
                converted_bits += query_bits.colBits[hash_position].size();
            }
            perf_log("generateReply.hash" + to_string(hash_position)
                + ".col_secure_lwe_to_rgsw_ms=" + to_string(precomputed_hashes[hash_position].colSecureMs)
                + ", convertedBitCount=" + to_string(query_bits.colBits[hash_position].size()));
            auto hash_step_start = Clock::now();
            string row_prefix = "hash" + to_string(hash_position) + ".row";
            vector<fusepirc::RawRgswCipher> row_rgsw_bits = fusepirc::secure_lwe_bits_to_rgsw_batch_cached_ntt(
                query_bits.rowBits[hash_position], evaluation_key, cb_params, row_prefix.c_str()
            );
            precomputed_hashes[hash_position].rowSecureMs = elapsed_ms(hash_step_start);
            converted_bits += query_bits.rowBits[hash_position].size();
            perf_log("generateReply.hash" + to_string(hash_position)
                + ".row_secure_lwe_to_rgsw_ms=" + to_string(precomputed_hashes[hash_position].rowSecureMs)
                + ", convertedBitCount=" + to_string(query_bits.rowBits[hash_position].size()));
            hash_step_start = Clock::now();
            precomputed_hashes[hash_position].rowRgswBitsNtt.reserve(row_rgsw_bits.size());
            for (const fusepirc::RawRgswCipher &row_rgsw_bit : row_rgsw_bits) {
                precomputed_hashes[hash_position].rowRgswBitsNtt.push_back(
                    fusepirc::make_cached_raw_rgsw_ntt(row_rgsw_bit, ntt_params));
            }
            precomputed_hashes[hash_position].rowRgswNttCacheMs = elapsed_ms(hash_step_start);
            perf_log("generateReply.hash" + to_string(hash_position)
                + ".row_rgsw_ntt_cache_ms=" + to_string(precomputed_hashes[hash_position].rowRgswNttCacheMs)
                + ", cachedBitCount=" + to_string(precomputed_hashes[hash_position].rowRgswBitsNtt.size()));
            hash_step_start = Clock::now();
            precomputed_hashes[hash_position].colRgswBitsNtt.reserve(col_rgsw_bits.size());
            for (const fusepirc::RawRgswCipher &col_rgsw_bit : col_rgsw_bits) {
                precomputed_hashes[hash_position].colRgswBitsNtt.push_back(
                    fusepirc::make_cached_raw_rgsw_ntt(col_rgsw_bit, ntt_params));
            }
            precomputed_hashes[hash_position].selectorMs = elapsed_ms(hash_step_start);
            precomputed_hashes[hash_position].convertedBitCount = converted_bits;
            total_secure_ms += precomputed_hashes[hash_position].colSecureMs
                + precomputed_hashes[hash_position].rowSecureMs;
            total_converted_bits += converted_bits;
            total_selector_ms += precomputed_hashes[hash_position].selectorMs;
            total_row_rgsw_ntt_cache_ms += precomputed_hashes[hash_position].rowRgswNttCacheMs;
            perf_log("generateReply.hash" + to_string(hash_position)
                + ".column_selector_cache_ms=" + to_string(precomputed_hashes[hash_position].selectorMs)
                + ", bitCount=" + to_string(precomputed_hashes[hash_position].colRgswBitsNtt.size()));
        }
        perf_log("generateReply.query_material_precompute"
            + string(", payloadBlockNum=") + to_string(encoded_matrix.payloadBlockNum)
            + ", blocksPerPackedMatrix=" + to_string(encoded_matrix.blocksPerPackedMatrix)
            + ", packedMatrixGroupNum=" + to_string(encoded_matrix.packedMatrixGroupNum)
            + ", convertedBitCount=" + to_string(total_converted_bits)
            + ", expectedConvertedBitCount=" + to_string(3 * (query.row_bit_num + query.col_bit_num))
            + ", blockLoopCount=" + to_string(encoded_matrix.packedMatrixGroupNum));
        uint64_t row_blind_rotate_count = 0;
        for (uint32_t group = 0; group < encoded_matrix.packedMatrixGroupNum; group++) {
            fusepirc::RawRlweCipher block_sum{
                fusepirc::zero_poly(cb_params.degree, cb_params.modulus),
                fusepirc::zero_poly(cb_params.degree, cb_params.modulus),
                cb_params.rlweParams,
                false,
                0
            };
            for (uint32_t hash_position = 0; hash_position < 3; hash_position++) {
                auto hash_step_start = Clock::now();
                fusepirc::RawNttWorkspace column_ntt_workspace;
                fusepirc::RawRlweCipher selected_column = fusepirc::select_plain_column_from_cached_rgsw_bits(
                    precomputed_hashes[hash_position].colRgswBitsNtt, encoded_matrix.columns[group],
                    encoded_matrix.colNum, cb_params.rlweParams, cb_params.externalProductParams,
                    cb_params.rgswLayout, column_ntt_workspace
                );
                uint64_t column_ms = elapsed_ms(hash_step_start);
                perf_log("generateReply.hash" + to_string(hash_position)
                    + ".column_selection_ms=" + to_string(column_ms)
                    + ", evaluation=recursive_cmux");
                hash_step_start = Clock::now();
                fusepirc::RawNttWorkspace row_ntt_workspace;
                fusepirc::RawRlweCipher selected_row = fusepirc::blind_rotate_row_to_zero_from_cached_rgsw_bits(
                    selected_column, precomputed_hashes[hash_position].rowRgswBitsNtt,
                    encoded_matrix.rowNum, encoded_matrix.rowStride,
                    cb_params.rlweParams, cb_params.externalProductParams, cb_params.rgswLayout,
                    row_ntt_workspace
                );
                uint64_t row_ms = elapsed_ms(hash_step_start);
                row_blind_rotate_count++;
                perf_log("generateReply.hash" + to_string(hash_position)
                    + ".row_blind_rotate_ms=" + to_string(row_ms));
                HashReplyResult result{
                    selected_row,
                    0,
                    0,
                    0,
                    column_ms,
                    0,
                    row_ms,
                    0
                };
                total_column_ms += result.columnMs;
                total_row_ms += result.rowBlindRotateMs;
                step_start = Clock::now();
                block_sum = fusepirc::raw_rlwe_add(block_sum, result.selectedRow);
                total_sum_ms += elapsed_ms(step_start);
            }
            response_blocks.push_back(block_sum);
        }
        if (response_blocks.size() != encoded_matrix.packedMatrixGroupNum
            || row_blind_rotate_count != static_cast<uint64_t>(3) * encoded_matrix.packedMatrixGroupNum) {
            throw invalid_argument("FUSE_PIR_C packed response shape mismatch");
        }
        uint64_t avg_bit_ms = total_converted_bits == 0 ? 0 : total_secure_ms / total_converted_bits;
        perf_log("generateReply.secure_lwe_to_rgsw_total_ms=" + to_string(total_secure_ms)
            + ", secure_lwe_to_rgsw_converted_bits=" + to_string(total_converted_bits)
            + ", secure_lwe_to_rgsw_avg_bit_ms=" + to_string(avg_bit_ms)
            + ", column_selector_cache_total_ms=" + to_string(total_selector_ms)
            + ", column_selection_total_ms=" + to_string(total_column_ms)
            + ", row_rgsw_ntt_cache_total_ms=" + to_string(total_row_rgsw_ntt_cache_ms)
            + ", row_blind_rotate_total_ms=" + to_string(total_row_ms)
            + ", rowBlindRotateCount=" + to_string(row_blind_rotate_count)
            + ", expectedRowBlindRotateCount=" + to_string(3 * encoded_matrix.packedMatrixGroupNum)
            + ", bff_share_sum_total_ms=" + to_string(total_sum_ms)
            + ", internal_total_ms=" + to_string(elapsed_ms(total_start)));
        return response_blocks;
    }
}

JNIEXPORT jbyteArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_generateEncryptionParams
    (JNIEnv *env, jclass, jint poly_modulus_degree, jlong plain_modulus, jintArray coeff_modulus_bits) {
    try {
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(static_cast<size_t>(poly_modulus_degree));
        parms.set_plain_modulus(static_cast<uint64_t>(plain_modulus));
        parms.set_coeff_modulus(CoeffModulus::Create(
            static_cast<size_t>(poly_modulus_degree), jint_array_to_vector(env, coeff_modulus_bits)
        ));
        SEALContext context = create_context_128(parms, "FUSE_PIR_C", __func__);
        log_bfv_parameter_summary("[FusePIR-C-PARAM]", "FusePIR-C", context, true);
        return serialize_encryption_parms(env, parms);
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_keyGen
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jobject lwe_params_obj) {
    try {
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "FUSE_PIR_C", __func__);
        fusepirc::LweParams lwe_params = read_lwe_params(env, lwe_params_obj);
        KeyGenerator key_gen(context);
        const SecretKey &secret_key = key_gen.secret_key();
        Serializable<PublicKey> public_key = key_gen.create_public_key();
        fusepirc::LweSecretKey lwe_secret_key = fusepirc::binary_lwe_keygen(lwe_params);
        jobject list = new_array_list(env);
        jbyteArray sk_bytes = serialize_secret_key(env, secret_key);
        jbyteArray pk_bytes = serialize_public_key(env, public_key);
        jbyteArray lwe_sk_bytes = vector_to_jbyte_array(env, fusepirc::serialize_lwe_secret_key(lwe_secret_key));
        list_add(env, list, sk_bytes);
        list_add(env, list, pk_bytes);
        list_add(env, list, lwe_sk_bytes);
        env->DeleteLocalRef(sk_bytes);
        env->DeleteLocalRef(pk_bytes);
        env->DeleteLocalRef(lwe_sk_bytes);
        return list;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jbyteArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_generateCompressedQuery
    (JNIEnv *env, jclass, jbyteArray, jbyteArray, jbyteArray, jbyteArray lwe_sk_bytes, jbyteArray, jintArray positions_array,
     jint row_num, jint col_num, jobject lwe_params_obj) {
    try {
        fusepirc::LweParams lwe_params = read_lwe_params(env, lwe_params_obj);
        fusepirc::LweSecretKey lwe_secret_key = fusepirc::deserialize_lwe_secret_key(
            jbyte_array_to_vector(env, lwe_sk_bytes)
        );
        if (lwe_secret_key.s.size() != lwe_params.n) {
            throw invalid_argument("FUSE_PIR_C LWE secret key dimension mismatch");
        }
        vector<int> positions = jint_array_to_int_vector(env, positions_array);
        if (positions.size() != 3) {
            throw invalid_argument("FUSE_PIR_C compressed query needs exactly three BFF positions");
        }
        if (row_num <= 0 || col_num <= 0) {
            throw invalid_argument("invalid FUSE_PIR_C matrix shape");
        }
        uint32_t row_bit_num = ceil_log2(static_cast<uint32_t>(row_num));
        uint32_t col_bit_num = ceil_log2(static_cast<uint32_t>(col_num));
        vector<uint8_t> query_seed = fusepirc::make_random_lwe_seed();
        fusepirc::CompressedLweBits query;
        query.seed = query_seed;
        query.row_bit_num = row_bit_num;
        query.col_bit_num = col_bit_num;
        query.bff_hash_num = 3;
        query.lwe_dimension = lwe_params.n;
        query.q = lwe_params.q;
        query.b_element_byte_length = b_element_byte_length(query.q);
        query.version = 1;
        query.b_array.reserve(query.bff_hash_num * (row_bit_num + col_bit_num));
        for (uint32_t hash_position = 0; hash_position < query.bff_hash_num; hash_position++) {
            int position = positions[hash_position];
            if (position < 0) {
                throw invalid_argument("negative FUSE_PIR_C BFF position");
            }
            uint32_t row = static_cast<uint32_t>(position) % static_cast<uint32_t>(row_num);
            uint32_t col = static_cast<uint32_t>(position) / static_cast<uint32_t>(row_num);
            if (col >= static_cast<uint32_t>(col_num)) {
                throw invalid_argument("FUSE_PIR_C BFF position exceeds matrix shape");
            }
            for (uint32_t bit_index = 0; bit_index < col_bit_num; bit_index++) {
                uint64_t bit = (col >> bit_index) & 1U;
                fusepirc::LweCipher cipher = fusepirc::lwe_encrypt_bit(
                    bit, lwe_secret_key, lwe_params, query_seed,
                    fusepirc::make_lwe_domain(hash_position, fusepirc::SelectorType::COL, bit_index)
                );
                query.b_array.push_back(cipher.b);
            }
            for (uint32_t bit_index = 0; bit_index < row_bit_num; bit_index++) {
                uint64_t bit = (row >> bit_index) & 1U;
                fusepirc::LweCipher cipher = fusepirc::lwe_encrypt_bit(
                    bit, lwe_secret_key, lwe_params, query_seed,
                    fusepirc::make_lwe_domain(hash_position, fusepirc::SelectorType::ROW, bit_index)
                );
                query.b_array.push_back(cipher.b);
            }
        }
        return vector_to_jbyte_array(env, fusepirc::serialize_compressed_lwe_bits(query));
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkPrgSameDomain
    (JNIEnv *env, jclass, jbyteArray seed_bytes, jint domain, jobject lwe_params_obj) {
    try {
        fusepirc::LweParams lwe_params = read_lwe_params(env, lwe_params_obj);
        vector<uint8_t> seed = jbyte_array_to_vector(env, seed_bytes);
        vector<uint64_t> a0 = fusepirc::prg_expand_lwe_a(seed, static_cast<uint64_t>(domain), lwe_params.n, lwe_params.q);
        vector<uint64_t> a1 = fusepirc::prg_expand_lwe_a(seed, static_cast<uint64_t>(domain), lwe_params.n, lwe_params.q);
        return a0 == a1;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkPrgDifferentDomain
    (JNIEnv *env, jclass, jbyteArray seed_bytes, jint domain0, jint domain1, jobject lwe_params_obj) {
    try {
        fusepirc::LweParams lwe_params = read_lwe_params(env, lwe_params_obj);
        vector<uint8_t> seed = jbyte_array_to_vector(env, seed_bytes);
        vector<uint64_t> a0 = fusepirc::prg_expand_lwe_a(seed, static_cast<uint64_t>(domain0), lwe_params.n, lwe_params.q);
        vector<uint64_t> a1 = fusepirc::prg_expand_lwe_a(seed, static_cast<uint64_t>(domain1), lwe_params.n, lwe_params.q);
        return a0 != a1;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkLweEncryptDecrypt
    (JNIEnv *env, jclass, jint bit, jobject lwe_params_obj) {
    try {
        fusepirc::LweParams lwe_params = read_lwe_params(env, lwe_params_obj);
        fusepirc::LweSecretKey sk = fusepirc::binary_lwe_keygen(lwe_params);
        vector<uint8_t> seed = fusepirc::make_random_lwe_seed();
        fusepirc::LweCipher cipher = fusepirc::lwe_encrypt_bit(
            static_cast<uint64_t>(bit), sk, lwe_params, seed,
            fusepirc::make_lwe_domain(0, fusepirc::SelectorType::COL, 0)
        );
        return fusepirc::lwe_decrypt_bit(cipher, sk, lwe_params) == static_cast<uint64_t>(bit);
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkCompressedQueryRecover
    (JNIEnv *env, jclass, jobject lwe_params_obj) {
    try {
        fusepirc::LweParams lwe_params = read_lwe_params(env, lwe_params_obj);
        fusepirc::LweSecretKey sk = fusepirc::binary_lwe_keygen(lwe_params);
        vector<uint8_t> seed = fusepirc::make_random_lwe_seed();
        fusepirc::CompressedLweBits query;
        query.seed = seed;
        query.row_bit_num = 2;
        query.col_bit_num = 2;
        query.bff_hash_num = 3;
        query.lwe_dimension = lwe_params.n;
        query.q = lwe_params.q;
        query.b_element_byte_length = b_element_byte_length(query.q);
        query.version = 1;
        vector<fusepirc::LweCipher> original;
        original.reserve(query.bff_hash_num * (query.row_bit_num + query.col_bit_num));
        for (uint32_t hash_position = 0; hash_position < query.bff_hash_num; hash_position++) {
            for (uint32_t bit_index = 0; bit_index < query.col_bit_num; bit_index++) {
                uint64_t bit = (hash_position + bit_index) & 1U;
                original.push_back(fusepirc::lwe_encrypt_bit(bit, sk, lwe_params, seed,
                    fusepirc::make_lwe_domain(hash_position, fusepirc::SelectorType::COL, bit_index)));
                query.b_array.push_back(original.back().b);
            }
            for (uint32_t bit_index = 0; bit_index < query.row_bit_num; bit_index++) {
                uint64_t bit = (hash_position + bit_index + 1) & 1U;
                original.push_back(fusepirc::lwe_encrypt_bit(bit, sk, lwe_params, seed,
                    fusepirc::make_lwe_domain(hash_position, fusepirc::SelectorType::ROW, bit_index)));
                query.b_array.push_back(original.back().b);
            }
        }
        fusepirc::CompressedLweBits decoded = fusepirc::deserialize_compressed_lwe_bits(
            fusepirc::serialize_compressed_lwe_bits(query)
        );
        vector<fusepirc::LweCipher> recovered = fusepirc::recover_lwe_bits_from_compressed_query(decoded);
        if (recovered.size() != original.size()) {
            return false;
        }
        for (size_t i = 0; i < original.size(); i++) {
            if (recovered[i].b != original[i].b || recovered[i].a != original[i].a) {
                return false;
            }
        }
        return true;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkRgswLayout
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray pk_bytes) {
    try {
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "FUSE_PIR_C", __func__);
        PublicKey public_key = deserialize_public_key(env, pk_bytes, context);
        RGSWCipher rgsw_zero = fusepirc::encrypt_rgsw_zero(context, public_key);
        RGSWCipher rgsw_one = fusepirc::encrypt_rgsw_one(context, public_key);
        fusepirc::validate_rgsw_layout(fusepirc::current_rgsw_layout(context), rgsw_zero);
        fusepirc::validate_rgsw_layout(fusepirc::current_rgsw_layout(context), rgsw_one);
        return true;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkCmux
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray sk_bytes, jbyteArray pk_bytes) {
    try {
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "FUSE_PIR_C", __func__);
        SecretKey secret_key = deserialize_secret_key(env, sk_bytes, context);
        PublicKey public_key = deserialize_public_key(env, pk_bytes, context);
        Encryptor encryptor(context, public_key);
        Ciphertext ct0;
        Ciphertext ct1;
        encryptor.encrypt(constant_plaintext(3), ct0);
        encryptor.encrypt(constant_plaintext(9), ct1);
        RGSWCipher rgsw_zero = fusepirc::encrypt_rgsw_zero(context, public_key);
        RGSWCipher rgsw_one = fusepirc::encrypt_rgsw_one(context, public_key);
        Ciphertext select_zero = fusepirc::cmux(rgsw_zero, ct1, ct0, context, public_key);
        Ciphertext select_one = fusepirc::cmux(rgsw_one, ct1, ct0, context, public_key);
        return decrypt_constant_coeff(select_zero, secret_key, context) == 3
            && decrypt_constant_coeff(select_one, secret_key, context) == 9;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

extern "C" JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkRawPolyMonomial
    (JNIEnv *env, jclass) {
    try {
        fusepirc::TorusPoly poly = fusepirc::zero_poly(4, 257);
        poly.coeffs[0] = 5;
        fusepirc::TorusPoly shifted = fusepirc::negacyclic_mul_monomial(poly, 4);
        return shifted.coeffs[0] == 252 && shifted.coeffs[1] == 0
            && shifted.coeffs[2] == 0 && shifted.coeffs[3] == 0;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

extern "C" JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkRawPolyAutomorphism
    (JNIEnv *env, jclass) {
    try {
        fusepirc::TorusPoly poly = fusepirc::zero_poly(4, 257);
        poly.coeffs[1] = 7;
        poly.coeffs[3] = 11;
        fusepirc::TorusPoly mapped = fusepirc::automorphism(poly, 3);
        return mapped.coeffs[0] == 0 && mapped.coeffs[1] == 11
            && mapped.coeffs[2] == 0 && mapped.coeffs[3] == 7;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

extern "C" JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkGadgetExact
    (JNIEnv *env, jclass) {
    try {
        fusepirc::TorusPoly poly = fusepirc::zero_poly(8, 65537);
        for (uint32_t i = 0; i < poly.degree; i++) {
            poly.coeffs[i] = (i * 12345 + 6789) % poly.modulus;
        }
        fusepirc::GadgetParams params{256, 8, 3, poly.modulus, true};
        vector<fusepirc::TorusPoly> digits = fusepirc::gadget_decompose_exact(poly, params);
        fusepirc::TorusPoly composed = fusepirc::gadget_compose_exact(digits, params);
        return composed.coeffs == poly.coeffs;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

extern "C" JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkRawRlweEncryptDecrypt
    (JNIEnv *env, jclass) {
    try {
        fusepirc::RawRlweParams params{16, UINT64_C(1) << 32, 32, false, {}};
        fusepirc::RawRlweSecretKey sk = fusepirc::raw_rlwe_keygen(params);
        fusepirc::TorusPoly message = fusepirc::zero_poly(params.degree, params.modulus);
        for (uint32_t i = 0; i < message.degree; i++) {
            message.coeffs[i] = static_cast<uint64_t>(i + 1) << 20;
        }
        fusepirc::RawRlweCipher ct = fusepirc::raw_rlwe_encrypt_poly(message, sk, params, 3.2);
        fusepirc::TorusPoly phase = fusepirc::raw_rlwe_decrypt_phase(ct, sk);
        for (uint32_t i = 0; i < message.degree; i++) {
            if (centered_distance(phase.coeffs[i], message.coeffs[i], params.modulus) > 64) {
                return false;
            }
        }
        return true;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

extern "C" JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkRawNttRoot
    (JNIEnv *env, jclass) {
    try {
        vector<pair<uint32_t, uint64_t>> cases{
            {16, 65537ULL},
            {2048, 18014398509404161ULL}
        };
        for (const auto &[degree, modulus] : cases) {
            fusepirc::RawNttParams params = fusepirc::make_raw_ntt_params(degree, modulus);
            uint64_t two_degree = static_cast<uint64_t>(2) * degree;
            if (fusepirc::raw_ntt_pow_mod(params.primitiveRoot2N, two_degree, modulus) != 1
                || fusepirc::raw_ntt_pow_mod(params.primitiveRoot2N, degree, modulus) != modulus - 1
                || fusepirc::raw_ntt_pow_mod(params.primitiveRootN, degree, modulus) != 1) {
                return false;
            }
        }
        return true;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

extern "C" JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkRawNttNegacyclicMulSmall
    (JNIEnv *env, jclass) {
    try {
        fusepirc::RawNttParams params = fusepirc::make_raw_ntt_params(16, 65537);
        fusepirc::TorusPoly a = fusepirc::zero_poly(params.degree, params.modulus);
        fusepirc::TorusPoly b = fusepirc::zero_poly(params.degree, params.modulus);
        for (uint32_t i = 0; i < params.degree; i++) {
            a.coeffs[i] = (i * 7919 + 17) % params.modulus;
            b.coeffs[i] = (i * i * 1237 + 99) % params.modulus;
        }
        fusepirc::TorusPoly naive = negacyclic_mul_poly_for_check(a, b);
        fusepirc::TorusPoly ntt = fusepirc::negacyclic_ntt_mul(a, b, params);
        return naive.coeffs == ntt.coeffs;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

extern "C" JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkRawNttNegacyclicMulCandidateSparse
    (JNIEnv *env, jclass) {
    try {
        fusepirc::RawNttParams params = fusepirc::make_raw_ntt_params(2048, 18014398509404161ULL);
        fusepirc::TorusPoly a = fusepirc::zero_poly(params.degree, params.modulus);
        fusepirc::TorusPoly b = fusepirc::zero_poly(params.degree, params.modulus);
        a.coeffs[0] = 7;
        a.coeffs[13] = 1234567;
        a.coeffs[2047] = 99;
        b.coeffs[0] = 3;
        b.coeffs[19] = 7654321;
        b.coeffs[1024] = 111;
        fusepirc::TorusPoly naive = negacyclic_mul_poly_for_check(a, b);
        fusepirc::TorusPoly ntt = fusepirc::negacyclic_ntt_mul(a, b, params);
        return naive.coeffs == ntt.coeffs;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

extern "C" JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkMvFbsModSwitchSign
    (JNIEnv *env, jclass) {
    try {
        fusepirc::MvFbsParams params = small_mv_fbs_params();
        fusepirc::LweCipher lwe;
        lwe.a = {16, 32, 48};
        lwe.b = 96;
        fusepirc::ModSwitchedLwe ms_lwe = fusepirc::mod_switch_for_blind_rotation(lwe, params);
        vector<uint64_t> secret = {1, 0, 1};
        int64_t exponent = ms_lwe.bBar;
        for (size_t i = 0; i < secret.size(); i++) {
            if (secret[i] != 0) {
                exponent -= ms_lwe.aBar[i];
            }
        }
        int64_t normalized = exponent % static_cast<int64_t>(params.rotationModulus);
        if (normalized < 0) {
            normalized += params.rotationModulus;
        }
        uint64_t phase = (lwe.b + params.lweModulus - ((lwe.a[0] + lwe.a[2]) % params.lweModulus))
            % params.lweModulus;
        uint64_t expected = static_cast<uint64_t>(
            (static_cast<__uint128_t>(phase) * params.rotationModulus * 2 + params.lweModulus)
            / (2 * params.lweModulus)
        ) % params.rotationModulus;
        return normalized == static_cast<int64_t>(expected)
            && ms_lwe.aBar[0] == 4 && ms_lwe.aBar[1] == 8 && ms_lwe.aBar[2] == 12 && ms_lwe.bBar == 24;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

extern "C" JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkMvFbsTestPolynomialLayout
    (JNIEnv *env, jclass) {
    try {
        fusepirc::MvFbsParams params = small_mv_fbs_params();
        uint64_t output_value = 1;
        uint64_t scaled = fusepirc::mul_mod_uint64(output_value, fusepirc::mod_inverse_uint64(
            (static_cast<uint64_t>(2) * params.degree) % params.modulus, params.modulus), params.modulus);
        uint64_t negative_scaled = scaled == 0 ? 0 : params.modulus - scaled;
        fusepirc::TorusPoly test_poly = fusepirc::build_mv_fbs_bit_test_polynomial(output_value, params);
        if (scaled != 63489 || negative_scaled != 2048
            || test_poly.degree != params.degree || test_poly.modulus != params.modulus) {
            return false;
        }
        for (uint32_t i = 0; i < params.degree; i++) {
            uint64_t expected = 0;
            if (i < params.degree / 4) {
                expected = negative_scaled;
            } else if (i >= 3 * params.degree / 4) {
                expected = scaled;
            }
            if (test_poly.coeffs[i] != expected) {
                return false;
            }
        }
        return true;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

extern "C" JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkRawExternalProductContract
    (JNIEnv *env, jclass) {
    try {
        fusepirc::MvFbsParams params = small_mv_fbs_params();
        fusepirc::RawExternalProductParams ep_params = small_raw_ep_params();
        fusepirc::RawRlweSecretKey sk = fusepirc::raw_rlwe_keygen(params.rlweParams);
        fusepirc::TorusPoly message = fusepirc::constant_poly(UINT64_C(1) << 24, params.degree, params.modulus);
        fusepirc::RawRlweCipher diff = fusepirc::raw_rlwe_encrypt_poly(message, sk, params.rlweParams, 0.1);
        fusepirc::RawRgswCipher rgsw_zero = fusepirc::raw_rgsw_encrypt_zero(sk, ep_params, 0.1);
        fusepirc::RawRgswCipher rgsw_one = fusepirc::raw_rgsw_encrypt_one(sk, ep_params, 0.1);
        fusepirc::TorusPoly phase_zero = fusepirc::raw_rlwe_decrypt_phase(
            fusepirc::raw_external_product(diff, rgsw_zero, ep_params), sk
        );
        fusepirc::TorusPoly phase_one = fusepirc::raw_rlwe_decrypt_phase(
            fusepirc::raw_external_product(diff, rgsw_one, ep_params), sk
        );
        return poly_close(phase_zero, fusepirc::zero_poly(params.degree, params.modulus), UINT64_C(1) << 24)
            && poly_close(phase_one, message, UINT64_C(1) << 24);
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

extern "C" JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkRawRgswCmuxContract
    (JNIEnv *env, jclass) {
    try {
        fusepirc::MvFbsParams params = small_mv_fbs_params();
        fusepirc::RawExternalProductParams ep_params = small_raw_ep_params();
        fusepirc::RawRlweSecretKey sk = fusepirc::raw_rlwe_keygen(params.rlweParams);
        fusepirc::TorusPoly message0 = fusepirc::constant_poly(UINT64_C(1) << 23, params.degree, params.modulus);
        fusepirc::TorusPoly message1 = fusepirc::constant_poly(UINT64_C(1) << 24, params.degree, params.modulus);
        fusepirc::RawRlweCipher ct0 = fusepirc::raw_rlwe_encrypt_poly(message0, sk, params.rlweParams, 0.1);
        fusepirc::RawRlweCipher ct1 = fusepirc::raw_rlwe_encrypt_poly(message1, sk, params.rlweParams, 0.1);
        fusepirc::RawRgswCipher rgsw_zero = fusepirc::raw_rgsw_encrypt_zero(sk, ep_params, 0.1);
        fusepirc::RawRgswCipher rgsw_one = fusepirc::raw_rgsw_encrypt_one(sk, ep_params, 0.1);
        fusepirc::TorusPoly select_zero = fusepirc::raw_rlwe_decrypt_phase(
            fusepirc::raw_cmux(rgsw_zero, ct1, ct0, ep_params), sk
        );
        fusepirc::TorusPoly select_one = fusepirc::raw_rlwe_decrypt_phase(
            fusepirc::raw_cmux(rgsw_one, ct1, ct0, ep_params), sk
        );
        return poly_close(select_zero, message0, UINT64_C(1) << 24)
            && poly_close(select_one, message1, UINT64_C(1) << 24);
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

extern "C" JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkRawExternalProductCachedNttConsistency
    (JNIEnv *env, jclass) {
    try {
        fusepirc::MvFbsParams params = small_mv_fbs_params();
        fusepirc::RawExternalProductParams ep_params = small_raw_ep_params();
        fusepirc::RawNttParams ntt_params = fusepirc::get_cached_raw_ntt_params(params.degree, params.modulus);
        fusepirc::RawRlweSecretKey sk = fusepirc::raw_rlwe_keygen(params.rlweParams);
        fusepirc::TorusPoly message0 = fusepirc::constant_poly(1234, params.degree, params.modulus);
        fusepirc::TorusPoly message1 = fusepirc::zero_poly(params.degree, params.modulus);
        message1.coeffs[2] = 4321;
        fusepirc::RawRlweCipher ct0 = fusepirc::raw_rlwe_encrypt_poly(message0, sk, params.rlweParams, 0.1);
        fusepirc::RawRlweCipher ct1 = fusepirc::raw_rlwe_encrypt_poly(message1, sk, params.rlweParams, 0.1);
        fusepirc::RawRgswCipher rgsw_zero = fusepirc::raw_rgsw_encrypt_zero(sk, ep_params, 0.1);
        fusepirc::RawRgswCipher rgsw_one = fusepirc::raw_rgsw_encrypt_one(sk, ep_params, 0.1);
        fusepirc::CachedRawRgswCipherNtt cached_zero = fusepirc::make_cached_raw_rgsw_ntt(rgsw_zero, ntt_params);
        fusepirc::CachedRawRgswCipherNtt cached_one = fusepirc::make_cached_raw_rgsw_ntt(rgsw_one, ntt_params);
        fusepirc::RawNttWorkspace workspace;
        fusepirc::RawRlweCipher diff = fusepirc::raw_rlwe_sub(ct1, ct0);
        fusepirc::RawRlweCipher old_product = fusepirc::raw_external_product(diff, rgsw_one, ep_params);
        fusepirc::RawRlweCipher cached_product = fusepirc::raw_external_product_cached_ntt(
            diff, cached_one, ep_params, workspace
        );
        fusepirc::RawRlweCipher cached_zero_select = fusepirc::raw_cmux_cached_ntt(
            cached_zero, ct1, ct0, ep_params, workspace
        );
        fusepirc::RawRlweCipher cached_one_select = fusepirc::raw_cmux_cached_ntt(
            cached_one, ct1, ct0, ep_params, workspace
        );
        return old_product.a.coeffs == cached_product.a.coeffs
            && old_product.b.coeffs == cached_product.b.coeffs
            && poly_close(fusepirc::raw_rlwe_decrypt_phase(cached_zero_select, sk), message0, 10000)
            && poly_close(fusepirc::raw_rlwe_decrypt_phase(cached_one_select, sk), message1, 10000);
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

extern "C" JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkMvFbsNoSampleExtractBit0Bit1
    (JNIEnv *env, jclass) {
    try {
        fusepirc::MvFbsParams params = small_mv_fbs_params();
        fusepirc::RawExternalProductParams ep_params = small_raw_ep_params();
        fusepirc::RawRlweSecretKey rlwe_sk = fusepirc::raw_rlwe_keygen(params.rlweParams);
        fusepirc::LweSecretKey lwe_sk;
        lwe_sk.s = {1, 0, 0};
        fusepirc::MvFbsKey key = fusepirc::generate_mv_fbs_key(lwe_sk, rlwe_sk, params, ep_params);
        vector<uint64_t> output_values = {1, 256, 65536};
        fusepirc::MvFbsTestPolynomialSet test_poly_set = fusepirc::build_mv_fbs_test_polynomial_set(output_values, params);
        fusepirc::LweCipher lwe_zero{{4, 0, 0}, 4};
        fusepirc::LweCipher lwe_one{{4, 0, 0}, 68};
        vector<fusepirc::RawRlweCipher> out_zero = fusepirc::mv_fbs_no_sample_extract(
            lwe_zero, key, test_poly_set, params, ep_params
        );
        vector<fusepirc::RawRlweCipher> out_one = fusepirc::mv_fbs_no_sample_extract(
            lwe_one, key, test_poly_set, params, ep_params
        );
        if (out_zero.size() != params.outputDigitNum || out_one.size() != params.outputDigitNum) {
            return false;
        }
        fusepirc::TorusPoly expected_zero = test_poly_set.testPolys[0];
        fusepirc::TorusPoly expected_one = fusepirc::negacyclic_mul_monomial(test_poly_set.testPolys[0], params.degree);
        return poly_close(fusepirc::raw_rlwe_decrypt_phase(out_zero[0], rlwe_sk), expected_zero, UINT64_C(1) << 25)
            && poly_close(fusepirc::raw_rlwe_decrypt_phase(out_one[0], rlwe_sk), expected_one, UINT64_C(1) << 25);
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

extern "C" JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkRawAutomorphismKeySwitchPhase
    (JNIEnv *env, jclass) {
    try {
        fusepirc::MvFbsParams params = small_mv_fbs_params();
        fusepirc::RawRlweSecretKey sk = fusepirc::raw_rlwe_keygen(params.rlweParams);
        uint32_t exponent = 5;
        fusepirc::RawAutomorphismKey aut_key = fusepirc::generate_raw_automorphism_key(
            sk, exponent, params.rlweParams, params.gadgetParams, 0.1
        );
        fusepirc::TorusPoly message = fusepirc::zero_poly(params.degree, params.modulus);
        message.coeffs[0] = 4096;
        message.coeffs[1] = 256;
        fusepirc::RawRlweCipher ct = fusepirc::raw_rlwe_encrypt_poly(message, sk, params.rlweParams, 0.1);
        fusepirc::RawRlweCipher ct_auto = fusepirc::apply_raw_rlwe_automorphism(ct, exponent);
        fusepirc::RawRlweCipher switched = fusepirc::raw_automorphism_key_switch(ct_auto, aut_key);
        fusepirc::TorusPoly expected = fusepirc::automorphism(message, exponent);
        fusepirc::TorusPoly phase = fusepirc::raw_rlwe_decrypt_phase(switched, sk);
        return poly_close(phase, expected, 4096);
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

extern "C" JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkHomTraceKillsNonconstantTerms
    (JNIEnv *env, jclass) {
    try {
        fusepirc::MvFbsParams mv_params = small_mv_fbs_params();
        fusepirc::HomTraceParams params = fusepirc::make_hom_trace_params(mv_params.rlweParams, mv_params.gadgetParams);
        fusepirc::RawRlweSecretKey sk = fusepirc::raw_rlwe_keygen(mv_params.rlweParams);
        fusepirc::HomTraceKey key = fusepirc::generate_hom_trace_key(sk, params, 0.1);
        fusepirc::TorusPoly message = fusepirc::zero_poly(mv_params.degree, mv_params.modulus);
        uint64_t c0 = 256;
        message.coeffs[0] = c0 / mv_params.degree;
        message.coeffs[1] = 32;
        message.coeffs[2] = 64;
        fusepirc::RawRlweCipher ct = fusepirc::raw_rlwe_encrypt_poly(message, sk, mv_params.rlweParams, 0.1);
        fusepirc::RawRlweCipher traced = fusepirc::hom_trace(ct, key, params);
        fusepirc::TorusPoly phase = fusepirc::raw_rlwe_decrypt_phase(traced, sk);
        fusepirc::TorusPoly expected = fusepirc::zero_poly(mv_params.degree, mv_params.modulus);
        expected.coeffs[0] = c0;
        return poly_close(phase, expected, 2048);
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

extern "C" JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkHomTraceManyMvFbsOutput
    (JNIEnv *env, jclass) {
    try {
        fusepirc::MvFbsParams mv_params = small_mv_fbs_params();
        fusepirc::RawExternalProductParams ep_params = small_raw_ep_params();
        fusepirc::HomTraceParams trace_params = fusepirc::make_hom_trace_params(mv_params.rlweParams,
            mv_params.gadgetParams);
        fusepirc::RawRlweSecretKey rlwe_sk = fusepirc::raw_rlwe_keygen(mv_params.rlweParams);
        fusepirc::HomTraceKey trace_key = fusepirc::generate_hom_trace_key(rlwe_sk, trace_params, 0.1);
        fusepirc::LweSecretKey lwe_sk;
        lwe_sk.s = {1, 0, 0};
        fusepirc::MvFbsKey mv_key = fusepirc::generate_mv_fbs_key(lwe_sk, rlwe_sk, mv_params, ep_params);
        vector<uint64_t> output_values = {1, 256, 65536};
        fusepirc::MvFbsTestPolynomialSet test_poly_set = fusepirc::build_mv_fbs_test_polynomial_set(output_values,
            mv_params);
        fusepirc::LweCipher lwe_zero{{4, 0, 0}, 4};
        fusepirc::LweCipher lwe_one{{4, 0, 0}, 68};
        vector<fusepirc::RawRlweCipher> out_zero = fusepirc::hom_trace_many(
            fusepirc::mv_fbs_no_sample_extract(lwe_zero, mv_key, test_poly_set, mv_params, ep_params),
            trace_key, trace_params
        );
        vector<fusepirc::RawRlweCipher> out_one = fusepirc::hom_trace_many(
            fusepirc::mv_fbs_no_sample_extract(lwe_one, mv_key, test_poly_set, mv_params, ep_params),
            trace_key, trace_params
        );
        if (out_zero.size() != output_values.size() || out_one.size() != output_values.size()) {
            return false;
        }
        fusepirc::TorusPoly expected_zero = fusepirc::zero_poly(mv_params.degree, mv_params.modulus);
        fusepirc::TorusPoly expected_one = fusepirc::zero_poly(mv_params.degree, mv_params.modulus);
        expected_one.coeffs[0] = output_values[0];
        return poly_close(fusepirc::raw_rlwe_decrypt_phase(out_zero[0], rlwe_sk), expected_zero, UINT64_C(1) << 29)
            && poly_close(fusepirc::raw_rlwe_decrypt_phase(out_one[0], rlwe_sk), expected_one, UINT64_C(1) << 29);
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

extern "C" JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkSchemeSwitchKeyGeneration
    (JNIEnv *env, jclass) {
    try {
        fusepirc::SchemeSwitchParams params = small_scheme_switch_params();
        fusepirc::RawRlweSecretKey sk = fusepirc::raw_rlwe_keygen(params.outputParams);
        fusepirc::SchemeSwitchKey key = fusepirc::generate_scheme_switch_key(sk, params, 0.1);
        fusepirc::TorusPoly expected = negacyclic_mul_poly_for_check(sk.s, sk.s);
        fusepirc::TorusPoly phase = fusepirc::raw_rlwe_decrypt_phase(key.encryptedSkSquare, sk);
        return key.encryptedSkSquare.params.degree == params.degree
            && key.encryptedSkSquare.params.modulus == params.modulus
            && poly_close(phase, expected, UINT64_C(1) << 24);
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

extern "C" JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkSchemeSwitchRawRgswLayout
    (JNIEnv *env, jclass) {
    try {
        fusepirc::SchemeSwitchParams params = small_scheme_switch_params();
        fusepirc::RawExternalProductParams ep_params = small_raw_ep_params();
        fusepirc::RawRlweSecretKey sk = fusepirc::raw_rlwe_keygen(params.outputParams);
        fusepirc::SchemeSwitchKey key = fusepirc::generate_scheme_switch_key(sk, params, 0.1);
        fusepirc::RawRgswCipher rgsw_zero = fusepirc::scheme_switch_to_raw_rgsw(
            make_traced_digits_for_bit(0, sk, params), key, params
        );
        fusepirc::RawRgswCipher rgsw_one = fusepirc::scheme_switch_to_raw_rgsw(
            make_traced_digits_for_bit(1, sk, params), key, params
        );
        fusepirc::validate_raw_rgsw_cipher(rgsw_zero, ep_params);
        fusepirc::validate_raw_rgsw_cipher(rgsw_one, ep_params);
        fusepirc::TorusPoly m0 = fusepirc::constant_poly(UINT64_C(1) << 23, params.degree, params.modulus);
        fusepirc::TorusPoly m1 = fusepirc::constant_poly(UINT64_C(1) << 24, params.degree, params.modulus);
        fusepirc::RawRlweCipher c0 = fusepirc::raw_rlwe_encrypt_poly(m0, sk, params.outputParams, 0.1);
        fusepirc::RawRlweCipher c1 = fusepirc::raw_rlwe_encrypt_poly(m1, sk, params.outputParams, 0.1);
        (void) fusepirc::raw_cmux(rgsw_zero, c1, c0, ep_params);
        (void) fusepirc::raw_cmux(rgsw_one, c1, c0, ep_params);
        return true;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

extern "C" JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkSchemeSwitchCmuxSemantics
    (JNIEnv *env, jclass) {
    try {
        fusepirc::SchemeSwitchParams params = small_scheme_switch_params();
        fusepirc::RawExternalProductParams ep_params = small_raw_ep_params();
        fusepirc::RawRlweSecretKey sk = fusepirc::raw_rlwe_keygen(params.outputParams);
        fusepirc::SchemeSwitchKey key = fusepirc::generate_scheme_switch_key(sk, params, 0.1);
        fusepirc::RawRgswCipher rgsw_zero = fusepirc::scheme_switch_to_raw_rgsw(
            make_traced_digits_for_bit(0, sk, params), key, params
        );
        fusepirc::RawRgswCipher rgsw_one = fusepirc::scheme_switch_to_raw_rgsw(
            make_traced_digits_for_bit(1, sk, params), key, params
        );
        fusepirc::TorusPoly m0 = fusepirc::constant_poly(UINT64_C(1) << 23, params.degree, params.modulus);
        fusepirc::TorusPoly m1 = fusepirc::constant_poly(UINT64_C(1) << 24, params.degree, params.modulus);
        fusepirc::RawRlweCipher c0 = fusepirc::raw_rlwe_encrypt_poly(m0, sk, params.outputParams, 0.1);
        fusepirc::RawRlweCipher c1 = fusepirc::raw_rlwe_encrypt_poly(m1, sk, params.outputParams, 0.1);
        fusepirc::TorusPoly select_zero = fusepirc::raw_rlwe_decrypt_phase(fusepirc::raw_cmux(rgsw_zero, c1, c0,
            ep_params), sk);
        fusepirc::TorusPoly select_one = fusepirc::raw_rlwe_decrypt_phase(fusepirc::raw_cmux(rgsw_one, c1, c0,
            ep_params), sk);
        return poly_close(select_zero, m0, UINT64_C(1) << 29)
            && poly_close(select_one, m1, UINT64_C(1) << 29);
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

extern "C" JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkCircuitBootstrapKeyGeneration
    (JNIEnv *env, jclass) {
    try {
        fusepirc::CircuitBootstrapParams params = small_circuit_bootstrap_params();
        auto keys = selector_check_keys(params);
        const fusepirc::CircuitBootstrapClientSecretState &client_state = keys.first;
        const fusepirc::CircuitBootstrapEvaluationKey &evaluation_key = keys.second;
        return client_state.lweSk.s.size() == params.lweParams.n
            && client_state.rlweSk.s.degree == params.degree
            && client_state.rlweSk.s.modulus == params.modulus
            && evaluation_key.mvFbsKey.bootstrappingKey.size() == params.lweParams.n
            && evaluation_key.homTraceKey.automorphismKeys.size()
                == params.homTraceParams.automorphismExponents.size()
            && evaluation_key.schemeSwitchKey.encryptedSkSquare.params.degree == params.degree
            && evaluation_key.schemeSwitchKey.encryptedSkSquare.params.modulus == params.modulus;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

extern "C" JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkTraceInverseScalingModInverse
    (JNIEnv *env, jclass) {
    try {
        fusepirc::CircuitBootstrapParams params = small_circuit_bootstrap_params();
        vector<uint64_t> output_values = {1, 256, 65536};
        for (uint64_t value : output_values) {
            uint64_t scaled = fusepirc::trace_inverse_scale_value(value, params.degree, params.modulus);
            uint64_t restored = fusepirc::mul_mod_uint64(scaled, params.degree, params.modulus);
            if (restored != value % params.modulus) {
                return false;
            }
        }
        return fusepirc::mod_inverse_uint64(params.degree, params.modulus) == 61441;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

extern "C" JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkSecureLweToRgswBit0Bit1Cmux
    (JNIEnv *env, jclass) {
    try {
        fusepirc::CircuitBootstrapParams params = small_circuit_bootstrap_params();
        auto keys = selector_check_keys(params);
        fusepirc::LweCipher lwe_zero{{0, 0, 0}, 1};
        fusepirc::LweCipher lwe_one{{0, 0, 0}, 65};
        fusepirc::RawRgswCipher rgsw_zero = fusepirc::secure_lwe_to_rgsw(lwe_zero, keys.second, params);
        fusepirc::RawRgswCipher rgsw_one = fusepirc::secure_lwe_to_rgsw(lwe_one, keys.second, params);
        fusepirc::TorusPoly m0 = fusepirc::constant_poly(0, params.degree, params.modulus);
        fusepirc::TorusPoly m1 = fusepirc::constant_poly(1, params.degree, params.modulus);
        fusepirc::RawRlweCipher c0 = fusepirc::trivial_raw_rlwe_constant(0, params.rlweParams);
        fusepirc::RawRlweCipher c1 = fusepirc::trivial_raw_rlwe_constant(1, params.rlweParams);
        fusepirc::TorusPoly select_zero = fusepirc::raw_rlwe_decrypt_phase(fusepirc::raw_cmux(
            rgsw_zero, c1, c0, params.externalProductParams
        ), keys.first.rlweSk);
        fusepirc::TorusPoly select_one = fusepirc::raw_rlwe_decrypt_phase(fusepirc::raw_cmux(
            rgsw_one, c1, c0, params.externalProductParams
        ), keys.first.rlweSk);
        return poly_close(select_zero, m0, 4096) && poly_close(select_one, m1, 4096);
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

extern "C" JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkCandidateSecureLweToRgswCmux
    (JNIEnv *env, jclass) {
    try {
        fusepirc::CircuitBootstrapParams params = cmux_128_candidate_circuit_bootstrap_params();
        auto keys = selector_check_keys(params);
        fusepirc::CachedCircuitBootstrapEvaluationKey cached_key =
            fusepirc::make_cached_circuit_bootstrap_key(keys.second, params);
        vector<uint8_t> seed = fusepirc::make_random_lwe_seed();
        auto explicit_error_lwe = [&](uint64_t bit, int64_t error, uint32_t bit_index) {
            fusepirc::LweCipher cipher;
            cipher.a = fusepirc::prg_expand_lwe_a(
                seed, fusepirc::make_lwe_domain(0, fusepirc::SelectorType::ROW, bit_index),
                params.lweParams.n, params.lweParams.q
            );
            uint64_t b = 0;
            for (size_t i = 0; i < cipher.a.size(); i++) {
                if (keys.first.lweSk.s[i] != 0) {
                    b = (b + cipher.a[i]) % params.lweParams.q;
                }
            }
            if (bit == 1) {
                b = (b + params.lweParams.delta) % params.lweParams.q;
            }
            if (error >= 0) {
                cipher.b = (b + static_cast<uint64_t>(error)) % params.lweParams.q;
            } else {
                uint64_t magnitude = static_cast<uint64_t>(-error) % params.lweParams.q;
                cipher.b = b >= magnitude ? b - magnitude : b + params.lweParams.q - magnitude;
            }
            return cipher;
        };
        fusepirc::CircuitBootstrapWorkspace workspace;
        fusepirc::RawNttParams ntt_params = fusepirc::get_cached_raw_ntt_params(params.degree, params.modulus);
        uint64_t encoded_zero_target = encode_payload_to_raw_torus(7, params.modulus);
        uint64_t encoded_one_target = encode_payload_to_raw_torus(11, params.modulus);
        uint64_t payload_tolerance = fusepirc_payload_scale(params.modulus) / 2;
        fusepirc::RawRlweCipher c0 = fusepirc::trivial_raw_rlwe_constant(encoded_zero_target, params.rlweParams);
        fusepirc::RawRlweCipher c1 = fusepirc::trivial_raw_rlwe_constant(encoded_one_target, params.rlweParams);
        fusepirc::RawNttWorkspace ntt_workspace;
        fusepirc::RawRgswCipher direct_zero = fusepirc::raw_rgsw_encrypt_zero(
            keys.first.rlweSk, params.externalProductParams, params.lweParams.sigma);
        fusepirc::RawRgswCipher direct_one = fusepirc::raw_rgsw_encrypt_one(
            keys.first.rlweSk, params.externalProductParams, params.lweParams.sigma);
        fusepirc::TorusPoly direct_zero_phase = fusepirc::raw_rlwe_decrypt_phase(fusepirc::raw_cmux_cached_ntt(
            fusepirc::make_cached_raw_rgsw_ntt(direct_zero, ntt_params), c1, c0, params.externalProductParams,
            ntt_workspace
        ), keys.first.rlweSk);
        fusepirc::TorusPoly direct_one_phase = fusepirc::raw_rlwe_decrypt_phase(fusepirc::raw_cmux_cached_ntt(
            fusepirc::make_cached_raw_rgsw_ntt(direct_one, ntt_params), c1, c0, params.externalProductParams,
            ntt_workspace
        ), keys.first.rlweSk);
        uint64_t direct_zero_distance = centered_distance(
            direct_zero_phase.coeffs[0], encoded_zero_target, params.modulus);
        uint64_t direct_one_distance = centered_distance(
            direct_one_phase.coeffs[0], encoded_one_target, params.modulus);
        perf_log("candidate.direct_raw_rgsw_cmux"
            + string(", zeroPhase=") + to_string(direct_zero_phase.coeffs[0])
            + ", zeroDistance=" + to_string(direct_zero_distance)
            + ", onePhase=" + to_string(direct_one_phase.coeffs[0])
            + ", oneDistance=" + to_string(direct_one_distance)
            + ", payloadTolerance=" + to_string(payload_tolerance));
        bool ok = true;
        ok = ok && direct_zero_distance <= payload_tolerance && direct_one_distance <= payload_tolerance;
        auto log_candidate_trace_digits = [&](uint64_t bit, const fusepirc::LweCipher &lwe) {
            vector<uint64_t> output_values = fusepirc::build_rgsw_gadget_output_values(
                params.gadgetParams, params.modulus);
            fusepirc::MvFbsTestPolynomialSet test_poly_set = fusepirc::build_mv_fbs_test_polynomial_set(
                output_values, params.mvFbsParams);
            uint64_t lwe_phase = fusepirc::lwe_decrypt_phase(lwe, keys.first.lweSk, params.lweParams);
            fusepirc::ModSwitchedLwe ms_lwe = fusepirc::mod_switch_for_blind_rotation(lwe, params.mvFbsParams);
            int64_t final_rotation = ms_lwe.bBar;
            for (size_t i = 0; i < ms_lwe.aBar.size(); i++) {
                if (keys.first.lweSk.s[i] != 0) {
                    final_rotation -= ms_lwe.aBar[i];
                }
            }
            int64_t normalized_rotation = final_rotation % static_cast<int64_t>(params.mvFbsParams.rotationModulus);
            if (normalized_rotation < 0) {
                normalized_rotation += params.mvFbsParams.rotationModulus;
            }
            perf_log("candidate.mv_fbs_rotation"
                + string(", bit=") + to_string(bit)
                + ", lwePhase=" + to_string(lwe_phase)
                + ", bBar=" + to_string(ms_lwe.bBar)
                + ", finalRotation=" + to_string(normalized_rotation)
                + ", rotationModulus=" + to_string(params.mvFbsParams.rotationModulus));
            fusepirc::RawNttWorkspace trace_ntt_workspace;
            vector<fusepirc::RawRlweCipher> mv_outputs = fusepirc::mv_fbs_no_sample_extract_cached_ntt(
                lwe, cached_key.mvFbsBootstrappingKeyNtt, test_poly_set, params.mvFbsParams,
                params.mvFbsExternalProductParams, trace_ntt_workspace);
            vector<fusepirc::RawRlweCipher> traced = fusepirc::hom_trace_many(
                mv_outputs, cached_key.coeffKey.homTraceKey, params.homTraceParams);
            for (uint32_t j = 0; j < traced.size(); j++) {
                uint64_t half_output = static_cast<uint64_t>(
                    (static_cast<__uint128_t>(output_values[j]) * ((params.modulus + 1) / 2)) % params.modulus);
                traced[j].b.coeffs[0] = static_cast<uint64_t>(
                    (static_cast<__uint128_t>(traced[j].b.coeffs[0]) + half_output) % params.modulus);
                fusepirc::TorusPoly mv_phase = fusepirc::raw_rlwe_decrypt_phase(mv_outputs[j], keys.first.rlweSk);
                uint64_t scaled_half = fusepirc::mul_mod_uint64(output_values[j], fusepirc::mod_inverse_uint64(
                    (static_cast<uint64_t>(2) * params.degree) % params.modulus, params.modulus), params.modulus);
                uint64_t expected_mv = bit == 0 ? (scaled_half == 0 ? 0 : params.modulus - scaled_half) : scaled_half;
                fusepirc::RawRlweCipher ideal_acc = fusepirc::init_mv_fbs_accumulator(
                    test_poly_set.testPolys[j], normalized_rotation, params.rlweParams);
                perf_log("candidate.mv_fbs_digit"
                    + string(", bit=") + to_string(bit)
                    + ", digit=" + to_string(j)
                    + ", coeff0=" + to_string(mv_phase.coeffs[0])
                    + ", idealCoeff0=" + to_string(ideal_acc.b.coeffs[0])
                    + ", expectedTraceInv=" + to_string(expected_mv)
                    + ", distance=" + to_string(centered_distance(mv_phase.coeffs[0], expected_mv, params.modulus)));
                fusepirc::TorusPoly phase = fusepirc::raw_rlwe_decrypt_phase(traced[j], keys.first.rlweSk);
                uint64_t expected = static_cast<uint64_t>(
                    (static_cast<__uint128_t>(output_values[j]) * bit) % params.modulus);
                perf_log("candidate.trace_digit"
                    + string(", bit=") + to_string(bit)
                    + ", digit=" + to_string(j)
                    + ", coeff0=" + to_string(phase.coeffs[0])
                    + ", expected=" + to_string(expected)
                    + ", distance=" + to_string(centered_distance(phase.coeffs[0], expected, params.modulus)));
            }
        };
        log_candidate_trace_digits(0, explicit_error_lwe(0, 0, 7));
        log_candidate_trace_digits(1, explicit_error_lwe(1, 0, 8));
        vector<int64_t> errors{0, 1, -1, 3, -3};
        for (int64_t error : errors) {
            fusepirc::RawRgswCipher rgsw_zero = fusepirc::secure_lwe_to_rgsw_with_workspace_cached_ntt(
                explicit_error_lwe(0, error, 0), cached_key, params, workspace
            );
            fusepirc::RawRgswCipher rgsw_one = fusepirc::secure_lwe_to_rgsw_with_workspace_cached_ntt(
                explicit_error_lwe(1, error, 1), cached_key, params, workspace
            );
            fusepirc::CachedRawRgswCipherNtt rgsw_zero_ntt = fusepirc::make_cached_raw_rgsw_ntt(rgsw_zero, ntt_params);
            fusepirc::CachedRawRgswCipherNtt rgsw_one_ntt = fusepirc::make_cached_raw_rgsw_ntt(rgsw_one, ntt_params);
            fusepirc::TorusPoly select_zero = fusepirc::raw_rlwe_decrypt_phase(fusepirc::raw_cmux_cached_ntt(
                rgsw_zero_ntt, c1, c0, params.externalProductParams, ntt_workspace
            ), keys.first.rlweSk);
            fusepirc::TorusPoly select_one = fusepirc::raw_rlwe_decrypt_phase(fusepirc::raw_cmux_cached_ntt(
                rgsw_one_ntt, c1, c0, params.externalProductParams, ntt_workspace
            ), keys.first.rlweSk);
            uint64_t zero_distance = centered_distance(select_zero.coeffs[0], encoded_zero_target, params.modulus);
            uint64_t one_distance = centered_distance(select_one.coeffs[0], encoded_one_target, params.modulus);
            perf_log("candidate.secure_lwe_to_rgsw_cmux"
                + string(", error=") + to_string(error)
                + ", zeroPhase=" + to_string(select_zero.coeffs[0])
                + ", zeroDistance=" + to_string(zero_distance)
                + ", onePhase=" + to_string(select_one.coeffs[0])
                + ", oneDistance=" + to_string(one_distance)
                + ", payloadTolerance=" + to_string(payload_tolerance));
            ok = ok && zero_distance <= payload_tolerance && one_distance <= payload_tolerance;
        }
        return ok;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

extern "C" JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkSecureLweBitsToRgswBatch
    (JNIEnv *env, jclass) {
    try {
        fusepirc::CircuitBootstrapParams params = small_circuit_bootstrap_params();
        auto keys = fusepirc::generate_circuit_bootstrap_keys(params, 0.1);
        vector<uint64_t> bits = {0, 1, 1, 0};
        vector<fusepirc::LweCipher> lwe_bits;
        for (uint64_t bit : bits) {
            lwe_bits.push_back(fusepirc::LweCipher{{0, 0, 0}, bit == 0 ? UINT64_C(1) : UINT64_C(65)});
        }
        vector<fusepirc::RawRgswCipher> rgsw_bits = fusepirc::secure_lwe_bits_to_rgsw(
            lwe_bits, keys.second, params
        );
        if (rgsw_bits.size() != bits.size()) {
            return false;
        }
        fusepirc::TorusPoly m0 = fusepirc::constant_poly(0, params.degree, params.modulus);
        fusepirc::TorusPoly m1 = fusepirc::constant_poly(1, params.degree, params.modulus);
        fusepirc::RawRlweCipher c0 = fusepirc::trivial_raw_rlwe_constant(0, params.rlweParams);
        fusepirc::RawRlweCipher c1 = fusepirc::trivial_raw_rlwe_constant(1, params.rlweParams);
        for (uint32_t i = 0; i < rgsw_bits.size(); i++) {
            fusepirc::TorusPoly selected = fusepirc::raw_rlwe_decrypt_phase(fusepirc::raw_cmux(
                rgsw_bits[i], c1, c0, params.externalProductParams
            ), keys.first.rlweSk);
            const fusepirc::TorusPoly &expected = bits[i] == 0 ? m0 : m1;
            if (!poly_close(selected, expected, 4096)) {
                return false;
            }
        }
        return true;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

extern "C" JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkSecureLweBitsToRgswBatchWorkspaceConsistency
    (JNIEnv *env, jclass) {
    try {
        fusepirc::CircuitBootstrapParams params = small_circuit_bootstrap_params();
        auto keys = fusepirc::generate_circuit_bootstrap_keys(params, 0.1);
        vector<uint64_t> bits = {0, 1};
        vector<fusepirc::LweCipher> lwe_bits;
        for (uint64_t bit : bits) {
            lwe_bits.push_back(fusepirc::LweCipher{{0, 0, 0}, bit == 0 ? UINT64_C(1) : UINT64_C(65)});
        }
        vector<fusepirc::RawRgswCipher> batch_bits = fusepirc::secure_lwe_bits_to_rgsw_batch(
            lwe_bits, keys.second, params, "workspace_consistency"
        );
        fusepirc::TorusPoly m0 = fusepirc::constant_poly(0, params.degree, params.modulus);
        fusepirc::TorusPoly m1 = fusepirc::constant_poly(1, params.degree, params.modulus);
        fusepirc::RawRlweCipher c0 = fusepirc::trivial_raw_rlwe_constant(0, params.rlweParams);
        fusepirc::RawRlweCipher c1 = fusepirc::trivial_raw_rlwe_constant(1, params.rlweParams);
        for (uint32_t i = 0; i < bits.size(); i++) {
            fusepirc::RawRgswCipher single = fusepirc::secure_lwe_to_rgsw(lwe_bits[i], keys.second, params);
            fusepirc::TorusPoly single_selected = fusepirc::raw_rlwe_decrypt_phase(fusepirc::raw_cmux(
                single, c1, c0, params.externalProductParams
            ), keys.first.rlweSk);
            fusepirc::TorusPoly batch_selected = fusepirc::raw_rlwe_decrypt_phase(fusepirc::raw_cmux(
                batch_bits[i], c1, c0, params.externalProductParams
            ), keys.first.rlweSk);
            const fusepirc::TorusPoly &expected = bits[i] == 0 ? m0 : m1;
            if (!poly_close(single_selected, expected, 4096)
                || !poly_close(batch_selected, expected, 4096)) {
                return false;
            }
        }
        return true;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

extern "C" JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkSelectorBitDecomposition
    (JNIEnv *env, jclass) {
    try {
        vector<uint64_t> bits4;
        for (uint32_t j = 0; j < ceil_log2(4); j++) {
            bits4.push_back((2 >> j) & 1U);
        }
        vector<uint64_t> bits8;
        for (uint32_t j = 0; j < ceil_log2(8); j++) {
            bits8.push_back((5 >> j) & 1U);
        }
        return bits4 == vector<uint64_t>({0, 1}) && bits8 == vector<uint64_t>({1, 0, 1});
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

extern "C" JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkSelectorLweBitPhase
    (JNIEnv *env, jclass) {
    try {
        fusepirc::CircuitBootstrapParams params = small_circuit_bootstrap_params();
        auto keys = selector_check_keys(params);
        vector<uint8_t> seed = fusepirc::make_random_lwe_seed();
        fusepirc::LweCipher bit_zero = fusepirc::lwe_encrypt_bit(
            0, keys.first.lweSk, params.lweParams, seed, fusepirc::make_lwe_domain(0, fusepirc::SelectorType::COL, 0)
        );
        fusepirc::LweCipher bit_one = fusepirc::lwe_encrypt_bit(
            1, keys.first.lweSk, params.lweParams, seed, fusepirc::make_lwe_domain(0, fusepirc::SelectorType::COL, 1)
        );
        return fusepirc::lwe_decrypt_bit(bit_zero, keys.first.lweSk, params.lweParams) == 0
            && fusepirc::lwe_decrypt_bit(bit_one, keys.first.lweSk, params.lweParams) == 1;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

extern "C" JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkRawRlwePrimeBasic
    (JNIEnv *env, jclass) {
    try {
        fusepirc::CircuitBootstrapParams params = small_circuit_bootstrap_params();
        fusepirc::RawRlwePrimeCipher one = fusepirc::trivial_raw_rlwe_prime_constant(
            1, params.rlweParams, params.gadgetParams
        );
        fusepirc::RawRlwePrimeCipher two = fusepirc::trivial_raw_rlwe_prime_constant(
            2, params.rlweParams, params.gadgetParams
        );
        fusepirc::RawRlwePrimeCipher sum = fusepirc::raw_rlwe_prime_add(one, one);
        fusepirc::RawRlwePrimeCipher diff = fusepirc::raw_rlwe_prime_sub(two, one);
        uint64_t gadget = 1 % params.modulus;
        for (uint32_t j = 0; j < params.gadgetLength; j++) {
            fusepirc::TorusPoly expected_gadget = fusepirc::constant_poly(gadget, params.degree, params.modulus);
            fusepirc::TorusPoly expected_double = fusepirc::constant_poly(
                static_cast<uint64_t>((static_cast<__uint128_t>(2) * gadget) % params.modulus),
                params.degree, params.modulus
            );
            if (one.digits[j].b.coeffs != expected_gadget.coeffs
                || sum.digits[j].b.coeffs != expected_double.coeffs
                || diff.digits[j].b.coeffs != expected_gadget.coeffs) {
                return false;
            }
            gadget = static_cast<uint64_t>((static_cast<__uint128_t>(gadget) * params.gadgetBase) % params.modulus);
        }
        return true;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

extern "C" JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkRawRgswMulRlwePrime
    (JNIEnv *env, jclass) {
    try {
        fusepirc::CircuitBootstrapParams params = small_circuit_bootstrap_params();
        auto keys = selector_check_keys(params);
        fusepirc::LweCipher lwe_zero{{0, 0, 0}, UINT64_C(1)};
        fusepirc::LweCipher lwe_one{{0, 0, 0}, params.lweParams.delta + 1};
        fusepirc::RawRgswCipher rgsw_zero = fusepirc::secure_lwe_to_rgsw(lwe_zero, keys.second, params);
        fusepirc::RawRgswCipher rgsw_one = fusepirc::secure_lwe_to_rgsw(lwe_one, keys.second, params);
        fusepirc::RawRlwePrimeCipher node = fusepirc::trivial_raw_rlwe_prime_constant(
            1, params.rlweParams, params.gadgetParams
        );
        fusepirc::RawRlwePrimeCipher out_zero = fusepirc::raw_rgsw_mul_rlwe_prime(
            rgsw_zero, node, params.externalProductParams, params.rgswLayout
        );
        fusepirc::RawRlwePrimeCipher out_one = fusepirc::raw_rgsw_mul_rlwe_prime(
            rgsw_one, node, params.externalProductParams, params.rgswLayout
        );
        uint64_t gadget = 1 % params.modulus;
        for (uint32_t j = 0; j < params.gadgetLength; j++) {
            fusepirc::TorusPoly zero_phase = fusepirc::raw_rlwe_decrypt_phase(out_zero.digits[j], keys.first.rlweSk);
            fusepirc::TorusPoly one_phase = fusepirc::raw_rlwe_decrypt_phase(out_one.digits[j], keys.first.rlweSk);
            fusepirc::TorusPoly expected_zero = fusepirc::zero_poly(params.degree, params.modulus);
            fusepirc::TorusPoly expected_one = fusepirc::constant_poly(gadget, params.degree, params.modulus);
            if (!poly_close(zero_phase, expected_zero, 4096) || !poly_close(one_phase, expected_one, 4096)) {
                return false;
            }
            gadget = static_cast<uint64_t>((static_cast<__uint128_t>(gadget) * params.gadgetBase) % params.modulus);
        }
        return true;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

extern "C" JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkOneHotSelectorFromSecureLweBits
    (JNIEnv *env, jclass) {
    try {
        fusepirc::CircuitBootstrapParams params = small_circuit_bootstrap_params();
        auto keys = selector_check_keys(params);
        uint32_t col_num = 4;
        uint32_t target_col = 2;
        vector<fusepirc::RawRgswCipher> col_bits = encrypt_index_bits_to_rgsw_for_selector_check(
            target_col, col_num, keys.first, keys.second, params, 1
        );
        vector<fusepirc::RawRlwePrimeCipher> selector = fusepirc::build_one_hot_selector_from_rgsw_bits(
            col_bits, col_num, params.rlweParams, params.gadgetParams, params.externalProductParams,
            params.rgswLayout
        );
        if (selector.size() != col_num) {
            return false;
        }
        for (uint32_t leaf = 0; leaf < col_num; leaf++) {
            uint64_t delta = leaf == target_col ? 1 : 0;
            uint64_t gadget = 1 % params.modulus;
            for (uint32_t j = 0; j < params.gadgetLength; j++) {
                fusepirc::TorusPoly phase = fusepirc::raw_rlwe_decrypt_phase(
                    selector[leaf].digits[j], keys.first.rlweSk
                );
                fusepirc::TorusPoly expected = fusepirc::constant_poly(
                    static_cast<uint64_t>((static_cast<__uint128_t>(gadget) * delta) % params.modulus),
                    params.degree, params.modulus
                );
                if (!poly_close(phase, expected, 4096)) {
                    return false;
                }
                gadget = static_cast<uint64_t>((static_cast<__uint128_t>(gadget) * params.gadgetBase)
                    % params.modulus);
            }
        }
        return true;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

extern "C" JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkOneHotColumnSelection
    (JNIEnv *env, jclass) {
    try {
        fusepirc::CircuitBootstrapParams params = small_circuit_bootstrap_params();
        auto keys = selector_check_keys(params);
        uint32_t col_num = 4;
        uint32_t target_col = 2;
        vector<fusepirc::RawRgswCipher> col_bits = encrypt_index_bits_to_rgsw_for_selector_check(
            target_col, col_num, keys.first, keys.second, params, 1
        );
        vector<fusepirc::RawRlwePrimeCipher> selector = fusepirc::build_one_hot_selector_from_rgsw_bits(
            col_bits, col_num, params.rlweParams, params.gadgetParams, params.externalProductParams,
            params.rgswLayout
        );
        vector<fusepirc::TorusPoly> columns;
        for (uint32_t c = 0; c < col_num; c++) {
            fusepirc::TorusPoly column = fusepirc::zero_poly(params.degree, params.modulus);
            column.coeffs[0] = 1 + c;
            columns.push_back(column);
        }
        fusepirc::RawRlwePrimeCipher selected = fusepirc::select_column_with_one_hot_selector(
            selector, columns, col_num, params.rlweParams, params.gadgetParams
        );
        uint64_t gadget = 1 % params.modulus;
        for (uint32_t j = 0; j < params.gadgetLength; j++) {
            fusepirc::TorusPoly phase = fusepirc::raw_rlwe_decrypt_phase(selected.digits[j], keys.first.rlweSk);
            fusepirc::TorusPoly expected = fusepirc::scalar_mul_mod(columns[target_col], gadget);
            if (!poly_close(phase, expected, 4096)) {
                return false;
            }
            gadget = static_cast<uint64_t>((static_cast<__uint128_t>(gadget) * params.gadgetBase) % params.modulus);
        }
        return true;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

extern "C" JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkOneHotSelectorBoundOne
    (JNIEnv *env, jclass) {
    try {
        fusepirc::CircuitBootstrapParams params = small_circuit_bootstrap_params();
        auto keys = selector_check_keys(params);
        vector<fusepirc::RawRgswCipher> empty_bits;
        vector<fusepirc::RawRlwePrimeCipher> selector = fusepirc::build_one_hot_selector_from_rgsw_bits(
            empty_bits, 1, params.rlweParams, params.gadgetParams, params.externalProductParams,
            params.rgswLayout
        );
        if (selector.size() != 1 || selector[0].digits.size() != params.gadgetLength) {
            return false;
        }
        uint64_t gadget = 1 % params.modulus;
        for (uint32_t j = 0; j < params.gadgetLength; j++) {
            fusepirc::TorusPoly phase = fusepirc::raw_rlwe_decrypt_phase(selector[0].digits[j], keys.first.rlweSk);
            fusepirc::TorusPoly expected = fusepirc::constant_poly(gadget, params.degree, params.modulus);
            if (!poly_close(phase, expected, 4096)) {
                return false;
            }
            gadget = static_cast<uint64_t>((static_cast<__uint128_t>(gadget) * params.gadgetBase) % params.modulus);
        }
        vector<fusepirc::TorusPoly> columns;
        fusepirc::TorusPoly only_column = fusepirc::zero_poly(params.degree, params.modulus);
        only_column.coeffs[0] = 12345;
        only_column.coeffs[3] = 23456;
        columns.push_back(only_column);
        fusepirc::RawRlweCipher selected = fusepirc::select_plain_column_with_one_hot_selector_to_raw_rlwe(
            selector, columns, 1, params.rlweParams, params.gadgetParams
        );
        fusepirc::TorusPoly selected_phase = fusepirc::raw_rlwe_decrypt_phase(selected, keys.first.rlweSk);
        return poly_close(selected_phase, only_column, 4096);
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

extern "C" JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkRowSelectorFromSecureLweBits
    (JNIEnv *env, jclass) {
    try {
        fusepirc::CircuitBootstrapParams params = small_circuit_bootstrap_params();
        auto keys = selector_check_keys(params);
        uint32_t row_num = 4;
        uint32_t row_stride = 2;
        auto check_target_row = [&](uint32_t target_row, uint64_t known_value) {
            vector<fusepirc::RawRgswCipher> row_bits = encrypt_index_bits_to_rgsw_for_selector_check(
                target_row, row_num, keys.first, keys.second, params, 1 + target_row
            );
            fusepirc::TorusPoly packed = fusepirc::zero_poly(params.degree, params.modulus);
            packed.coeffs[0] = 1000;
            packed.coeffs[row_stride] = 20000;
            packed.coeffs[2 * row_stride] = 50000;
            packed.coeffs[3 * row_stride] = 35000;
            packed.coeffs[target_row * row_stride] = known_value;
            fusepirc::RawRlweCipher packed_column{
                fusepirc::zero_poly(params.degree, params.modulus),
                packed,
                params.rlweParams,
                false,
                0
            };
            fusepirc::RawRlweCipher rotated = fusepirc::blind_rotate_row_to_zero_from_rgsw_bits(
                packed_column, row_bits, row_num, row_stride, params.rlweParams, params.externalProductParams,
                params.rgswLayout
            );
            fusepirc::TorusPoly phase = fusepirc::raw_rlwe_decrypt_phase(rotated, keys.first.rlweSk);
            return centered_distance(phase.coeffs[0], known_value, params.modulus) <= 12000;
        };
        return check_target_row(0, 12345) && check_target_row(2, 50000);
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

extern "C" JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkSelectorNoPlainIndexDependency
    (JNIEnv *env, jclass) {
    try {
        fusepirc::CircuitBootstrapParams params = small_circuit_bootstrap_params();
        auto keys = selector_check_keys(params);
        vector<fusepirc::RawRgswCipher> one_bit = encrypt_index_bits_to_rgsw_for_selector_check(
            0, 2, keys.first, keys.second, params, 2
        );
        bool one_hot_fail_closed = false;
        try {
            (void) fusepirc::build_one_hot_selector_from_rgsw_bits(
                one_bit, 4, params.rlweParams, params.gadgetParams, params.externalProductParams,
                params.rgswLayout
            );
        } catch (const invalid_argument &) {
            one_hot_fail_closed = true;
        }
        bool row_fail_closed = false;
        try {
            fusepirc::RawRlweCipher packed = fusepirc::trivial_raw_rlwe_constant(0, params.rlweParams);
            (void) fusepirc::blind_rotate_row_to_zero_from_rgsw_bits(
                packed, one_bit, 2, 0, params.rlweParams, params.externalProductParams, params.rgswLayout
            );
        } catch (const invalid_argument &) {
            row_fail_closed = true;
        }
        return one_hot_fail_closed && row_fail_closed;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

extern "C" JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkEvalKeyHandleLifecycle
    (JNIEnv *env, jclass) {
    try {
        fusepirc::CircuitBootstrapParams params = small_circuit_bootstrap_params();
        auto keys = selector_check_keys(params);
        fusepirc::CachedCircuitBootstrapEvaluationKey cached_key =
            fusepirc::make_cached_circuit_bootstrap_key(keys.second, params);
        uint64_t handle = register_evaluation_key(
            make_shared<fusepirc::CachedCircuitBootstrapEvaluationKey>(std::move(cached_key))
        );
        if (handle == 0 || !get_evaluation_key(handle)) {
            return false;
        }
        unregister_evaluation_key(handle);
        bool destroyed_fail_closed = false;
        try {
            (void) get_evaluation_key(handle);
        } catch (const invalid_argument &) {
            destroyed_fail_closed = true;
        }
        unregister_evaluation_key(handle);
        bool invalid_fail_closed = false;
        try {
            (void) get_evaluation_key(UINT64_C(0xFFFFFFFFFFFFFFF0));
        } catch (const invalid_argument &) {
            invalid_fail_closed = true;
        }
        return destroyed_fail_closed && invalid_fail_closed;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

extern "C" JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkRawMatrixHandleLifecycle
    (JNIEnv *env, jclass) {
    try {
        fusepirc::CircuitBootstrapParams params = small_circuit_bootstrap_params();
        FusePirCRawEncodedMatrix matrix;
        matrix.rowNum = 4;
        matrix.colNum = 4;
        matrix.rowStride = 1;
        matrix.payloadBlockNum = 1;
        matrix.blocksPerPackedMatrix = 1;
        matrix.packedMatrixGroupNum = 1;
        matrix.bffHashNum = 3;
        matrix.columns.resize(matrix.packedMatrixGroupNum);
        for (uint32_t g = 0; g < matrix.packedMatrixGroupNum; g++) {
            matrix.columns[g].resize(matrix.colNum, fusepirc::zero_poly(params.degree, params.modulus));
        }
        validate_raw_encoded_matrix(matrix, params.rlweParams);
        uint64_t handle = register_raw_matrix(make_shared<FusePirCRawEncodedMatrix>(matrix));
        if (handle == 0 || !get_raw_matrix(handle)) {
            return false;
        }
        unregister_raw_matrix(handle);
        bool destroyed_fail_closed = false;
        try {
            (void) get_raw_matrix(handle);
        } catch (const invalid_argument &) {
            destroyed_fail_closed = true;
        }
        unregister_raw_matrix(handle);
        bool invalid_fail_closed = false;
        try {
            (void) get_raw_matrix(UINT64_C(0xFFFFFFFFFFFFFFF1));
        } catch (const invalid_argument &) {
            invalid_fail_closed = true;
        }
        return destroyed_fail_closed && invalid_fail_closed;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

extern "C" JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkFusePirCNativeGenerateReplyMinimalRaw
    (JNIEnv *env, jclass) {
    try {
        fusepirc::CircuitBootstrapParams params = small_circuit_bootstrap_params();
        auto keys = selector_check_keys(params);
        uint32_t row_num = 4;
        uint32_t col_num = 4;
        uint32_t payload_block_num = 3;
        uint32_t blocks_per_packed_matrix = 3;
        uint32_t packed_matrix_group_num = 1;
        uint32_t row_stride = blocks_per_packed_matrix;
        array<uint32_t, 3> target_cols{1, 2, 3};
        array<uint32_t, 3> target_rows{0, 1, 2};
        array<array<uint64_t, 3>, 3> known_shares{{
            {1, 10, 100},
            {2, 20, 200},
            {3, 30, 300}
        }};

        fusepirc::CompressedLweBits query;
        query.seed = fusepirc::make_random_lwe_seed();
        query.row_bit_num = ceil_log2(row_num);
        query.col_bit_num = ceil_log2(col_num);
        query.bff_hash_num = 3;
        query.lwe_dimension = params.lweParams.n;
        query.q = params.lweParams.q;
        query.b_element_byte_length = b_element_byte_length(query.q);
        query.version = 1;
        query.b_array.reserve(3 * (query.row_bit_num + query.col_bit_num));
        for (uint32_t hash_position = 0; hash_position < 3; hash_position++) {
            for (uint32_t bit_index = 0; bit_index < query.col_bit_num; bit_index++) {
                uint64_t bit = (target_cols[hash_position] >> bit_index) & 1U;
                fusepirc::LweCipher lwe = fusepirc::lwe_encrypt_bit(
                    bit, keys.first.lweSk, params.lweParams, query.seed,
                    fusepirc::make_lwe_domain(hash_position, fusepirc::SelectorType::COL, bit_index)
                );
                query.b_array.push_back(lwe.b);
            }
            for (uint32_t bit_index = 0; bit_index < query.row_bit_num; bit_index++) {
                uint64_t bit = (target_rows[hash_position] >> bit_index) & 1U;
                fusepirc::LweCipher lwe = fusepirc::lwe_encrypt_bit(
                    bit, keys.first.lweSk, params.lweParams, query.seed,
                    fusepirc::make_lwe_domain(hash_position, fusepirc::SelectorType::ROW, bit_index)
                );
                query.b_array.push_back(lwe.b);
            }
        }

        FusePirCRawEncodedMatrix matrix;
        matrix.rowNum = row_num;
        matrix.colNum = col_num;
        matrix.rowStride = row_stride;
        matrix.payloadBlockNum = payload_block_num;
        matrix.blocksPerPackedMatrix = blocks_per_packed_matrix;
        matrix.packedMatrixGroupNum = packed_matrix_group_num;
        matrix.bffHashNum = 3;
        matrix.columns.resize(packed_matrix_group_num);
        for (uint32_t g = 0; g < packed_matrix_group_num; g++) {
            matrix.columns[g].resize(col_num, fusepirc::zero_poly(params.degree, params.modulus));
        }
        for (uint32_t h = 0; h < 3; h++) {
            for (uint32_t p = 0; p < payload_block_num; p++) {
                uint32_t g = p / blocks_per_packed_matrix;
                uint32_t local = p % blocks_per_packed_matrix;
                matrix.columns[g][target_cols[h]].coeffs[target_rows[h] * blocks_per_packed_matrix + local] =
                    known_shares[h][p];
            }
        }

        fusepirc::CachedCircuitBootstrapEvaluationKey cached_key =
            fusepirc::make_cached_circuit_bootstrap_key(keys.second, params);
        vector<fusepirc::RawRlweCipher> response = generate_fusepirc_raw_reply(query, cached_key, params, matrix);
        vector<uint8_t> serialized = serialize_raw_rlwe_cipher_vector(
            response, matrix.payloadBlockNum, matrix.blocksPerPackedMatrix, matrix.packedMatrixGroupNum);
        FusePirCRawResponse decoded = deserialize_raw_response(serialized);
        if (serialized.empty() || decoded.blocks.size() != packed_matrix_group_num
            || decoded.payloadBlockNum != payload_block_num
            || decoded.blocksPerPackedMatrix != blocks_per_packed_matrix) {
            return false;
        }
        for (uint32_t p = 0; p < payload_block_num; p++) {
            uint32_t g = p / blocks_per_packed_matrix;
            uint32_t local = p % blocks_per_packed_matrix;
            fusepirc::TorusPoly phase = fusepirc::raw_rlwe_decrypt_phase(decoded.blocks[g], keys.first.rlweSk);
            uint64_t expected = (known_shares[0][p] + known_shares[1][p] + known_shares[2][p]) % params.modulus;
            if (centered_distance(phase.coeffs[local], expected, params.modulus) > 12000) {
                return false;
            }
        }
        return true;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

extern "C" JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_generateCircuitBootstrapKeyMaterialForCheck
    (JNIEnv *env, jclass) {
    try {
        fusepirc::CircuitBootstrapParams params = small_circuit_bootstrap_params();
        auto keys = selector_check_keys(params);
        uint32_t row_num = 4;
        uint32_t col_num = 4;
        uint32_t payload_block_num = 1;
        uint32_t row_stride = 1;
        array<uint32_t, 3> target_cols{1, 2, 3};
        array<uint32_t, 3> target_rows{0, 1, 2};
        array<uint64_t, 3> known_shares{1, 2, 3};

        fusepirc::CompressedLweBits query;
        query.seed = fusepirc::make_random_lwe_seed();
        query.row_bit_num = ceil_log2(row_num);
        query.col_bit_num = ceil_log2(col_num);
        query.bff_hash_num = 3;
        query.lwe_dimension = params.lweParams.n;
        query.q = params.lweParams.q;
        query.b_element_byte_length = b_element_byte_length(query.q);
        query.version = 1;
        query.b_array.reserve(3 * (query.row_bit_num + query.col_bit_num));
        for (uint32_t hash_position = 0; hash_position < 3; hash_position++) {
            for (uint32_t bit_index = 0; bit_index < query.col_bit_num; bit_index++) {
                uint64_t bit = (target_cols[hash_position] >> bit_index) & 1U;
                fusepirc::LweCipher lwe = fusepirc::lwe_encrypt_bit(
                    bit, keys.first.lweSk, params.lweParams, query.seed,
                    fusepirc::make_lwe_domain(hash_position, fusepirc::SelectorType::COL, bit_index)
                );
                query.b_array.push_back(lwe.b);
            }
            for (uint32_t bit_index = 0; bit_index < query.row_bit_num; bit_index++) {
                uint64_t bit = (target_rows[hash_position] >> bit_index) & 1U;
                fusepirc::LweCipher lwe = fusepirc::lwe_encrypt_bit(
                    bit, keys.first.lweSk, params.lweParams, query.seed,
                    fusepirc::make_lwe_domain(hash_position, fusepirc::SelectorType::ROW, bit_index)
                );
                query.b_array.push_back(lwe.b);
            }
        }

        FusePirCRawEncodedMatrix matrix;
        matrix.rowNum = row_num;
        matrix.colNum = col_num;
        matrix.rowStride = row_stride;
        matrix.payloadBlockNum = payload_block_num;
        matrix.blocksPerPackedMatrix = row_stride;
        matrix.packedMatrixGroupNum = (payload_block_num + matrix.blocksPerPackedMatrix - 1)
            / matrix.blocksPerPackedMatrix;
        matrix.bffHashNum = 3;
        matrix.columns.resize(matrix.packedMatrixGroupNum);
        for (uint32_t g = 0; g < matrix.packedMatrixGroupNum; g++) {
            matrix.columns[g].resize(col_num, fusepirc::zero_poly(params.degree, params.modulus));
        }
        for (uint32_t h = 0; h < 3; h++) {
            for (uint32_t p = 0; p < payload_block_num; p++) {
                uint32_t g = p / matrix.blocksPerPackedMatrix;
                uint32_t local = p % matrix.blocksPerPackedMatrix;
                matrix.columns[g][target_cols[h]].coeffs[target_rows[h] * matrix.blocksPerPackedMatrix + local] =
                    known_shares[h];
            }
        }

        jobject list = new_array_list(env);
        vector<vector<uint8_t>> payloads{
            serialize_circuit_bootstrap_params(params),
            serialize_circuit_bootstrap_client_secret(keys.first),
            serialize_circuit_bootstrap_evaluation_key(keys.second),
            fusepirc::serialize_compressed_lwe_bits(query),
            serialize_raw_encoded_matrix(matrix)
        };
        for (const vector<uint8_t> &payload : payloads) {
            jbyteArray item = vector_to_jbyte_array(env, payload);
            list_add(env, list, item);
            env->DeleteLocalRef(item);
        }
        return list;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

extern "C" JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_generateCircuitBootstrapSetupMaterial
    (JNIEnv *env, jclass) {
    try {
        auto total_start = Clock::now();
        fusepirc::CircuitBootstrapParams params = cmux_128_candidate_circuit_bootstrap_params();
        auto keys = selector_check_keys(params);
        jobject list = new_array_list(env);
        auto step_start = Clock::now();
        vector<uint8_t> params_payload = serialize_circuit_bootstrap_params(params);
        perf_log("setup.serialize.circuitBootstrapParams_ms=" + to_string(elapsed_ms(step_start))
            + ", bytes=" + to_string(params_payload.size()));
        step_start = Clock::now();
        vector<uint8_t> secret_payload = serialize_circuit_bootstrap_client_secret(keys.first);
        perf_log("setup.serialize.clientSecretState_ms=" + to_string(elapsed_ms(step_start))
            + ", bytes=" + to_string(secret_payload.size()));
        step_start = Clock::now();
        vector<uint8_t> eval_payload = serialize_circuit_bootstrap_evaluation_key(keys.second);
        perf_log("setup.serialize.evaluationKey_ms=" + to_string(elapsed_ms(step_start))
            + ", setupEvaluationKeyBytes=" + to_string(eval_payload.size()));
        vector<vector<uint8_t>> payloads{
            std::move(params_payload),
            std::move(secret_payload),
            std::move(eval_payload)
        };
        for (const vector<uint8_t> &payload : payloads) {
            jbyteArray item = vector_to_jbyte_array(env, payload);
            list_add(env, list, item);
            env->DeleteLocalRef(item);
        }
        perf_log("setup.generateCircuitBootstrapSetupMaterial.total_ms=" + to_string(elapsed_ms(total_start)));
        return list;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

extern "C" JNIEXPORT jbyteArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_generateCompressedQueryFromClientSecret
    (JNIEnv *env, jclass, jbyteArray client_secret_bytes, jbyteArray, jintArray positions_array, jint row_num,
     jint col_num, jbyteArray params_bytes) {
    try {
        auto total_start = Clock::now();
        if (row_num <= 0 || col_num <= 0) {
            throw invalid_argument("invalid FUSE_PIR_C matrix shape");
        }
        auto step_start = Clock::now();
        fusepirc::CircuitBootstrapParams params = deserialize_circuit_bootstrap_params(
            jbyte_array_to_vector(env, params_bytes)
        );
        fusepirc::CircuitBootstrapClientSecretState client_secret = deserialize_circuit_bootstrap_client_secret(
            jbyte_array_to_vector(env, client_secret_bytes)
        );
        vector<int> positions = jint_array_to_int_vector(env, positions_array);
        perf_log("client.query.parse_secret_and_params_ms=" + to_string(elapsed_ms(step_start)));
        if (positions.size() != 3 || client_secret.lweSk.s.size() != params.lweParams.n) {
            throw invalid_argument("invalid FUSE_PIR_C query input");
        }
        uint32_t row_bit_num = ceil_log2(static_cast<uint32_t>(row_num));
        uint32_t col_bit_num = ceil_log2(static_cast<uint32_t>(col_num));
        fusepirc::CompressedLweBits query;
        query.seed = fusepirc::make_random_lwe_seed();
        query.row_bit_num = row_bit_num;
        query.col_bit_num = col_bit_num;
        query.bff_hash_num = 3;
        query.lwe_dimension = params.lweParams.n;
        query.q = params.lweParams.q;
        query.b_element_byte_length = b_element_byte_length(query.q);
        query.version = 1;
        query.b_array.reserve(3 * (row_bit_num + col_bit_num));
        step_start = Clock::now();
        for (uint32_t hash_position = 0; hash_position < 3; hash_position++) {
            int position = positions[hash_position];
            if (position < 0) {
                throw invalid_argument("negative FUSE_PIR_C position");
            }
            uint32_t row = static_cast<uint32_t>(position) % static_cast<uint32_t>(row_num);
            uint32_t col = static_cast<uint32_t>(position) / static_cast<uint32_t>(row_num);
            if (col >= static_cast<uint32_t>(col_num)) {
                throw invalid_argument("FUSE_PIR_C position exceeds matrix shape");
            }
            for (uint32_t bit_index = 0; bit_index < col_bit_num; bit_index++) {
                uint64_t bit = (col >> bit_index) & 1U;
                fusepirc::LweCipher lwe = fusepirc::lwe_encrypt_bit(
                    bit, client_secret.lweSk, params.lweParams, query.seed,
                    fusepirc::make_lwe_domain(hash_position, fusepirc::SelectorType::COL, bit_index)
                );
                query.b_array.push_back(lwe.b);
            }
            for (uint32_t bit_index = 0; bit_index < row_bit_num; bit_index++) {
                uint64_t bit = (row >> bit_index) & 1U;
                fusepirc::LweCipher lwe = fusepirc::lwe_encrypt_bit(
                    bit, client_secret.lweSk, params.lweParams, query.seed,
                    fusepirc::make_lwe_domain(hash_position, fusepirc::SelectorType::ROW, bit_index)
                );
                query.b_array.push_back(lwe.b);
            }
        }
        perf_log("client.query.lwe_bArray_generation_ms=" + to_string(elapsed_ms(step_start))
            + ", bCount=" + to_string(query.b_array.size())
            + ", bElementBytes=" + to_string(query.b_element_byte_length));
        step_start = Clock::now();
        vector<uint8_t> serialized = fusepirc::serialize_compressed_lwe_bits(query);
        perf_log("client.query.serialization_ms=" + to_string(elapsed_ms(step_start))
            + ", seedBytes=" + to_string(query.seed.size())
            + ", bArrayBytes=" + to_string(query.b_array.size() * query.b_element_byte_length)
            + ", metadataBytes=44"
            + ", implementationOnlineQueryBytes=" + to_string(serialized.size())
            + ", canonicalOnlineQueryBytes=" + to_string(query.seed.size()
                + query.b_array.size() * query.b_element_byte_length)
            + ", total_ms=" + to_string(elapsed_ms(total_start)));
        return vector_to_jbyte_array(env, serialized);
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

extern "C" JNIEXPORT jbyteArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_encodeRawMatrixForEntries
    (JNIEnv *env, jclass, jintArray flat_positions_array, jlongArray values_array, jint row_num, jint col_num,
     jint payload_block_num, jint row_stride, jbyteArray params_bytes) {
    try {
        auto total_start = Clock::now();
        if (row_num <= 0 || col_num <= 0 || payload_block_num <= 0 || row_stride <= 0) {
            throw invalid_argument("invalid FUSE_PIR_C raw matrix metadata");
        }
        auto step_start = Clock::now();
        fusepirc::CircuitBootstrapParams params = deserialize_circuit_bootstrap_params(
            jbyte_array_to_vector(env, params_bytes)
        );
        perf_log("server.init.rawMatrix.parse_params_ms=" + to_string(elapsed_ms(step_start)));
        if (static_cast<uint64_t>(row_num) * static_cast<uint64_t>(row_stride) > params.degree) {
            throw invalid_argument("FUSE_PIR_C raw matrix row packing exceeds raw RLWE degree");
        }
        step_start = Clock::now();
        vector<int> flat_positions = jint_array_to_int_vector(env, flat_positions_array);
        jsize value_count = env->GetArrayLength(values_array);
        if (value_count <= 0 || value_count % payload_block_num != 0) {
            throw invalid_argument("FUSE_PIR_C raw matrix value block count mismatch");
        }
        size_t entry_count = static_cast<size_t>(value_count / payload_block_num);
        jlong *value_elements = env->GetLongArrayElements(values_array, nullptr);
        if (value_elements == nullptr) {
            throw runtime_error("failed to access FUSE_PIR_C raw matrix values");
        }
        vector<uint64_t> values(static_cast<size_t>(value_count));
        for (jsize i = 0; i < value_count; i++) {
            values[static_cast<size_t>(i)] = encode_payload_to_raw_torus(
                static_cast<uint64_t>(value_elements[i]), params.modulus
            );
        }
        env->ReleaseLongArrayElements(values_array, value_elements, JNI_ABORT);
        if (flat_positions.size() != entry_count * 3) {
            throw invalid_argument("FUSE_PIR_C raw matrix positions/value size mismatch");
        }
        perf_log("server.init.rawMatrix.parse_entries_ms=" + to_string(elapsed_ms(step_start))
            + ", entryCount=" + to_string(entry_count)
            + ", payloadBlockNum=" + to_string(payload_block_num));
        step_start = Clock::now();
        FusePirCRawEncodedMatrix matrix;
        matrix.rowNum = static_cast<uint32_t>(row_num);
        matrix.colNum = static_cast<uint32_t>(col_num);
        matrix.rowStride = static_cast<uint32_t>(row_stride);
        matrix.payloadBlockNum = static_cast<uint32_t>(payload_block_num);
        matrix.blocksPerPackedMatrix = matrix.rowStride;
        matrix.packedMatrixGroupNum =
            (matrix.payloadBlockNum + matrix.blocksPerPackedMatrix - 1) / matrix.blocksPerPackedMatrix;
        matrix.bffHashNum = 3;
        matrix.columns.resize(matrix.packedMatrixGroupNum);
        for (uint32_t g = 0; g < matrix.packedMatrixGroupNum; g++) {
            matrix.columns[g].resize(matrix.colNum, fusepirc::zero_poly(params.degree, params.modulus));
        }
        for (uint32_t entry = 0; entry < entry_count; entry++) {
            for (uint32_t h = 0; h < 3; h++) {
                int position = flat_positions[entry * 3 + h];
                if (position < 0) {
                    throw invalid_argument("negative raw matrix position");
                }
                uint32_t row = static_cast<uint32_t>(position) % matrix.rowNum;
                uint32_t col = static_cast<uint32_t>(position) / matrix.rowNum;
                if (col >= matrix.colNum) {
                    throw invalid_argument("raw matrix position exceeds shape");
                }
                for (uint32_t p = 0; p < matrix.payloadBlockNum; p++) {
                    uint32_t packed_group = p / matrix.blocksPerPackedMatrix;
                    uint32_t local_block = p % matrix.blocksPerPackedMatrix;
                    uint32_t coeff_index = row * matrix.blocksPerPackedMatrix + local_block;
                    if (packed_group >= matrix.packedMatrixGroupNum || coeff_index >= params.degree) {
                        throw invalid_argument("FUSE_PIR_C raw matrix packed coefficient index exceeds raw RLWE degree");
                    }
                    // Deprecated minimal-test helper only. Formal FUSE_PIR_C server init uses
                    // encodeRawMatrixFromBffStorage with real BFF additive storage.
                    uint64_t share = 0;
                    if (h == 0) {
                        share = values[entry * matrix.payloadBlockNum + p];
                    }
                    matrix.columns[packed_group][col].coeffs[coeff_index] =
                        (matrix.columns[packed_group][col].coeffs[coeff_index] + share) % params.modulus;
                }
            }
        }
        validate_raw_encoded_matrix(matrix, params.rlweParams);
        perf_log("server.init.rawMatrix.encode_ms=" + to_string(elapsed_ms(step_start))
            + ", rowNum=" + to_string(matrix.rowNum)
            + ", colNum=" + to_string(matrix.colNum)
            + ", payloadBlockNum=" + to_string(matrix.payloadBlockNum)
            + ", blocksPerPackedMatrix=" + to_string(matrix.blocksPerPackedMatrix)
            + ", packedMatrixGroupNum=" + to_string(matrix.packedMatrixGroupNum));
        step_start = Clock::now();
        vector<uint8_t> serialized = serialize_raw_encoded_matrix(matrix);
        perf_log("server.init.rawMatrix.serialization_ms=" + to_string(elapsed_ms(step_start))
            + ", rawEncodedMatrixBytes=" + to_string(serialized.size())
            + ", total_ms=" + to_string(elapsed_ms(total_start)));
        return vector_to_jbyte_array(env, serialized);
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

extern "C" JNIEXPORT jbyteArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_encodeRawMatrixFromBffStorage
    (JNIEnv *env, jclass, jlongArray storage_by_block_array, jint bff_slot_num, jint row_num, jint col_num,
     jint payload_block_num, jint row_stride, jbyteArray params_bytes) {
    try {
        auto total_start = Clock::now();
        if (bff_slot_num <= 0 || row_num <= 0 || col_num <= 0 || payload_block_num <= 0 || row_stride <= 0) {
            throw invalid_argument("invalid FUSE_PIR_C BFF raw matrix metadata");
        }
        auto step_start = Clock::now();
        fusepirc::CircuitBootstrapParams params = deserialize_circuit_bootstrap_params(
            jbyte_array_to_vector(env, params_bytes)
        );
        perf_log("server.init.rawBffMatrix.parse_params_ms=" + to_string(elapsed_ms(step_start)));
        if (static_cast<uint64_t>(row_num) * static_cast<uint64_t>(col_num) < static_cast<uint64_t>(bff_slot_num)) {
            throw invalid_argument("FUSE_PIR_C BFF slot count exceeds raw matrix shape");
        }
        if (static_cast<uint64_t>(row_num) * static_cast<uint64_t>(row_stride) > params.degree) {
            throw invalid_argument("FUSE_PIR_C BFF packed row exceeds raw RLWE degree");
        }
        uint32_t blocks_per_packed_matrix = static_cast<uint32_t>(row_stride);
        uint32_t packed_matrix_group_num =
            (static_cast<uint32_t>(payload_block_num) + blocks_per_packed_matrix - 1) / blocks_per_packed_matrix;
        jsize storage_count = env->GetArrayLength(storage_by_block_array);
        if (storage_count != static_cast<jsize>(payload_block_num * bff_slot_num)) {
            throw invalid_argument("FUSE_PIR_C BFF storage dimension mismatch");
        }
        jlong *storage_elements = env->GetLongArrayElements(storage_by_block_array, nullptr);
        if (storage_elements == nullptr) {
            throw runtime_error("failed to access FUSE_PIR_C BFF storage");
        }
        vector<uint64_t> storage(static_cast<size_t>(storage_count));
        for (jsize i = 0; i < storage_count; i++) {
            if (storage_elements[i] < 0) {
                env->ReleaseLongArrayElements(storage_by_block_array, storage_elements, JNI_ABORT);
                throw invalid_argument("negative FUSE_PIR_C BFF storage value");
            }
            storage[static_cast<size_t>(i)] = static_cast<uint64_t>(storage_elements[i]) % params.modulus;
        }
        env->ReleaseLongArrayElements(storage_by_block_array, storage_elements, JNI_ABORT);

        step_start = Clock::now();
        FusePirCRawEncodedMatrix matrix;
        matrix.rowNum = static_cast<uint32_t>(row_num);
        matrix.colNum = static_cast<uint32_t>(col_num);
        matrix.rowStride = blocks_per_packed_matrix;
        matrix.payloadBlockNum = static_cast<uint32_t>(payload_block_num);
        matrix.blocksPerPackedMatrix = blocks_per_packed_matrix;
        matrix.packedMatrixGroupNum = packed_matrix_group_num;
        matrix.bffHashNum = 3;
        matrix.columns.resize(matrix.packedMatrixGroupNum);
        for (uint32_t g = 0; g < matrix.packedMatrixGroupNum; g++) {
            matrix.columns[g].resize(matrix.colNum, fusepirc::zero_poly(params.degree, params.modulus));
        }
        for (uint32_t p = 0; p < matrix.payloadBlockNum; p++) {
            uint32_t packed_group = p / matrix.blocksPerPackedMatrix;
            uint32_t local_block = p % matrix.blocksPerPackedMatrix;
            for (uint32_t slot = 0; slot < static_cast<uint32_t>(bff_slot_num); slot++) {
                uint32_t row = slot % matrix.rowNum;
                uint32_t col = slot / matrix.rowNum;
                if (col >= matrix.colNum) {
                    throw invalid_argument("FUSE_PIR_C BFF storage slot exceeds matrix shape");
                }
                uint32_t coeff_index = row * matrix.blocksPerPackedMatrix + local_block;
                if (packed_group >= matrix.packedMatrixGroupNum || coeff_index >= params.degree) {
                    throw invalid_argument("FUSE_PIR_C BFF packed coefficient index exceeds raw RLWE degree");
                }
                uint64_t value = storage[static_cast<size_t>(p) * static_cast<size_t>(bff_slot_num) + slot];
                matrix.columns[packed_group][col].coeffs[coeff_index] = value;
            }
        }
        validate_raw_encoded_matrix(matrix, params.rlweParams);
        perf_log("server.init.rawBffMatrix.pack_ms=" + to_string(elapsed_ms(step_start))
            + ", bffSlotNum=" + to_string(bff_slot_num)
            + ", rowNum=" + to_string(matrix.rowNum)
            + ", colNum=" + to_string(matrix.colNum)
            + ", payloadBlockNum=" + to_string(matrix.payloadBlockNum)
            + ", blocksPerPackedMatrix=" + to_string(matrix.blocksPerPackedMatrix)
            + ", packedMatrixGroupNum=" + to_string(matrix.packedMatrixGroupNum));
        step_start = Clock::now();
        vector<uint8_t> serialized = serialize_raw_encoded_matrix(matrix);
        perf_log("server.init.rawBffMatrix.serialization_ms=" + to_string(elapsed_ms(step_start))
            + ", rawEncodedMatrixBytes=" + to_string(serialized.size())
            + ", total_ms=" + to_string(elapsed_ms(total_start)));
        return vector_to_jbyte_array(env, serialized);
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

extern "C" JNIEXPORT jbyteArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_encodeRawMatrixFromBffStorageBlocks
    (JNIEnv *env, jclass, jobjectArray storage_by_block_array, jint bff_slot_num, jint row_num, jint col_num,
     jint payload_block_num, jint row_stride, jbyteArray params_bytes) {
    try {
        auto total_start = Clock::now();
        if (bff_slot_num <= 0 || row_num <= 0 || col_num <= 0 || payload_block_num <= 0 || row_stride <= 0) {
            throw invalid_argument("invalid FUSE_PIR_C BFF raw matrix metadata");
        }
        auto step_start = Clock::now();
        fusepirc::CircuitBootstrapParams params = deserialize_circuit_bootstrap_params(
            jbyte_array_to_vector(env, params_bytes)
        );
        perf_log("server.init.rawBffMatrixBlocks.parse_params_ms=" + to_string(elapsed_ms(step_start)));
        if (static_cast<uint64_t>(row_num) * static_cast<uint64_t>(col_num) < static_cast<uint64_t>(bff_slot_num)) {
            throw invalid_argument("FUSE_PIR_C BFF slot count exceeds raw matrix shape");
        }
        if (static_cast<uint64_t>(row_num) * static_cast<uint64_t>(row_stride) > params.degree) {
            throw invalid_argument("FUSE_PIR_C BFF packed row exceeds raw RLWE degree");
        }
        if (env->GetArrayLength(storage_by_block_array) != payload_block_num) {
            throw invalid_argument("FUSE_PIR_C BFF storage block dimension mismatch");
        }
        uint32_t blocks_per_packed_matrix = static_cast<uint32_t>(row_stride);
        uint32_t packed_matrix_group_num =
            (static_cast<uint32_t>(payload_block_num) + blocks_per_packed_matrix - 1) / blocks_per_packed_matrix;

        step_start = Clock::now();
        FusePirCRawEncodedMatrix matrix;
        matrix.rowNum = static_cast<uint32_t>(row_num);
        matrix.colNum = static_cast<uint32_t>(col_num);
        matrix.rowStride = blocks_per_packed_matrix;
        matrix.payloadBlockNum = static_cast<uint32_t>(payload_block_num);
        matrix.blocksPerPackedMatrix = blocks_per_packed_matrix;
        matrix.packedMatrixGroupNum = packed_matrix_group_num;
        matrix.bffHashNum = 3;
        matrix.columns.resize(matrix.packedMatrixGroupNum);
        for (uint32_t g = 0; g < matrix.packedMatrixGroupNum; g++) {
            matrix.columns[g].resize(matrix.colNum, fusepirc::zero_poly(params.degree, params.modulus));
        }
        for (uint32_t p = 0; p < matrix.payloadBlockNum; p++) {
            jobject block_obj = env->GetObjectArrayElement(storage_by_block_array, static_cast<jsize>(p));
            if (block_obj == nullptr) {
                throw invalid_argument("FUSE_PIR_C BFF storage block is null");
            }
            jlongArray block_array = reinterpret_cast<jlongArray>(block_obj);
            if (env->GetArrayLength(block_array) != bff_slot_num) {
                env->DeleteLocalRef(block_obj);
                throw invalid_argument("FUSE_PIR_C BFF storage slot dimension mismatch");
            }
            jlong *block_elements = env->GetLongArrayElements(block_array, nullptr);
            if (block_elements == nullptr) {
                env->DeleteLocalRef(block_obj);
                throw runtime_error("failed to access FUSE_PIR_C BFF storage block");
            }
            uint32_t packed_group = p / matrix.blocksPerPackedMatrix;
            uint32_t local_block = p % matrix.blocksPerPackedMatrix;
            for (uint32_t slot = 0; slot < static_cast<uint32_t>(bff_slot_num); slot++) {
                if (block_elements[slot] < 0) {
                    env->ReleaseLongArrayElements(block_array, block_elements, JNI_ABORT);
                    env->DeleteLocalRef(block_obj);
                    throw invalid_argument("negative FUSE_PIR_C BFF storage value");
                }
                uint32_t row = slot % matrix.rowNum;
                uint32_t col = slot / matrix.rowNum;
                if (col >= matrix.colNum) {
                    env->ReleaseLongArrayElements(block_array, block_elements, JNI_ABORT);
                    env->DeleteLocalRef(block_obj);
                    throw invalid_argument("FUSE_PIR_C BFF storage slot exceeds matrix shape");
                }
                uint32_t coeff_index = row * matrix.blocksPerPackedMatrix + local_block;
                if (packed_group >= matrix.packedMatrixGroupNum || coeff_index >= params.degree) {
                    env->ReleaseLongArrayElements(block_array, block_elements, JNI_ABORT);
                    env->DeleteLocalRef(block_obj);
                    throw invalid_argument("FUSE_PIR_C BFF packed coefficient index exceeds raw RLWE degree");
                }
                uint64_t value = static_cast<uint64_t>(block_elements[slot]) % params.modulus;
                matrix.columns[packed_group][col].coeffs[coeff_index] = value;
            }
            env->ReleaseLongArrayElements(block_array, block_elements, JNI_ABORT);
            env->DeleteLocalRef(block_obj);
        }
        validate_raw_encoded_matrix(matrix, params.rlweParams);
        perf_log("server.init.rawBffMatrixBlocks.pack_ms=" + to_string(elapsed_ms(step_start))
            + ", bffSlotNum=" + to_string(bff_slot_num)
            + ", rowNum=" + to_string(matrix.rowNum)
            + ", colNum=" + to_string(matrix.colNum)
            + ", payloadBlockNum=" + to_string(matrix.payloadBlockNum)
            + ", blocksPerPackedMatrix=" + to_string(matrix.blocksPerPackedMatrix)
            + ", packedMatrixGroupNum=" + to_string(matrix.packedMatrixGroupNum));
        step_start = Clock::now();
        vector<uint8_t> serialized = serialize_raw_encoded_matrix(matrix);
        perf_log("server.init.rawBffMatrixBlocks.serialization_ms=" + to_string(elapsed_ms(step_start))
            + ", rawEncodedMatrixBytes=" + to_string(serialized.size())
            + ", total_ms=" + to_string(elapsed_ms(total_start)));
        return vector_to_jbyte_array(env, serialized);
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

extern "C" JNIEXPORT jlong JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_createCircuitBootstrapEvaluationKey
    (JNIEnv *env, jclass, jbyteArray params_bytes, jbyteArray eval_key_bytes) {
    try {
        auto total_start = Clock::now();
        auto step_start = Clock::now();
        fusepirc::CircuitBootstrapParams params = deserialize_circuit_bootstrap_params(
            jbyte_array_to_vector(env, params_bytes)
        );
        perf_log("server.init.evalKey.parse_params_ms=" + to_string(elapsed_ms(step_start)));
        step_start = Clock::now();
        fusepirc::CircuitBootstrapEvaluationKey key = deserialize_circuit_bootstrap_evaluation_key(
            jbyte_array_to_vector(env, eval_key_bytes), params
        );
        perf_log("server.init.evalKey.deserialization_ms=" + to_string(elapsed_ms(step_start)));
        step_start = Clock::now();
        fusepirc::CachedCircuitBootstrapEvaluationKey cached_key =
            fusepirc::make_cached_circuit_bootstrap_key(std::move(key), params);
        perf_log("server.init.evalKey.ntt_cache_ms=" + to_string(elapsed_ms(step_start))
            + ", cachedMvFbsRgswCount=" + to_string(cached_key.mvFbsBootstrappingKeyNtt.size()));
        step_start = Clock::now();
        uint64_t handle = register_evaluation_key(
            make_shared<fusepirc::CachedCircuitBootstrapEvaluationKey>(std::move(cached_key))
        );
        perf_log("server.init.evalKey.handle_registration_ms=" + to_string(elapsed_ms(step_start))
            + ", handle=" + to_string(handle)
            + ", total_ms=" + to_string(elapsed_ms(total_start)));
        return static_cast<jlong>(handle);
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return 0;
    }
}

extern "C" JNIEXPORT void JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_destroyCircuitBootstrapEvaluationKey
    (JNIEnv *, jclass, jlong handle) {
    unregister_evaluation_key(static_cast<uint64_t>(handle));
}

extern "C" JNIEXPORT jlong JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_createRawMatrix
    (JNIEnv *env, jclass, jbyteArray raw_matrix_bytes, jbyteArray params_bytes) {
    try {
        auto total_start = Clock::now();
        auto step_start = Clock::now();
        fusepirc::CircuitBootstrapParams params = deserialize_circuit_bootstrap_params(
            jbyte_array_to_vector(env, params_bytes)
        );
        perf_log("server.init.rawMatrixHandle.parse_params_ms=" + to_string(elapsed_ms(step_start)));
        step_start = Clock::now();
        FusePirCRawEncodedMatrix matrix = deserialize_raw_encoded_matrix(
            jbyte_array_to_vector(env, raw_matrix_bytes), params.rlweParams
        );
        perf_log("server.init.rawMatrixHandle.deserialization_ms=" + to_string(elapsed_ms(step_start)));
        step_start = Clock::now();
        cache_raw_matrix_column_decomposition(matrix, params.gadgetParams);
        perf_log("server.init.rawMatrixHandle.column_decomposition_cache_ms=" + to_string(elapsed_ms(step_start)));
        step_start = Clock::now();
        uint64_t handle = register_raw_matrix(make_shared<FusePirCRawEncodedMatrix>(std::move(matrix)));
        perf_log("server.init.rawMatrixHandle.registration_ms=" + to_string(elapsed_ms(step_start))
            + ", handle=" + to_string(handle)
            + ", total_ms=" + to_string(elapsed_ms(total_start)));
        return static_cast<jlong>(handle);
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return 0;
    }
}

extern "C" JNIEXPORT jlong JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_createEmptyRawMatrix
    (JNIEnv *env, jclass, jint row_num, jint col_num, jint payload_block_num, jint row_stride,
     jbyteArray params_bytes) {
    try {
        if (row_num <= 0 || col_num <= 0 || payload_block_num <= 0 || row_stride <= 0) {
            throw invalid_argument("invalid empty FUSE_PIR_C raw matrix metadata");
        }
        fusepirc::CircuitBootstrapParams params = deserialize_circuit_bootstrap_params(
            jbyte_array_to_vector(env, params_bytes)
        );
        if (static_cast<uint64_t>(row_num) * static_cast<uint64_t>(row_stride) > params.degree) {
            throw invalid_argument("FUSE_PIR_C empty raw matrix rows exceed raw RLWE degree");
        }
        auto matrix = make_shared<FusePirCRawEncodedMatrix>();
        matrix->rowNum = static_cast<uint32_t>(row_num);
        matrix->colNum = static_cast<uint32_t>(col_num);
        matrix->rowStride = static_cast<uint32_t>(row_stride);
        matrix->payloadBlockNum = static_cast<uint32_t>(payload_block_num);
        matrix->blocksPerPackedMatrix = matrix->rowStride;
        matrix->packedMatrixGroupNum =
            (matrix->payloadBlockNum + matrix->blocksPerPackedMatrix - 1) / matrix->blocksPerPackedMatrix;
        matrix->bffHashNum = 3;
        matrix->columns.resize(matrix->packedMatrixGroupNum);
        for (uint32_t g = 0; g < matrix->packedMatrixGroupNum; g++) {
            matrix->columns[g].resize(matrix->colNum, fusepirc::zero_poly(params.degree, params.modulus));
        }
        uint64_t handle = register_raw_matrix(std::move(matrix));
        perf_log("server.init.rawMatrixHandle.create_empty"
            + string(", rowNum=") + to_string(row_num)
            + ", colNum=" + to_string(col_num)
            + ", payloadBlockNum=" + to_string(payload_block_num)
            + ", rowStride=" + to_string(row_stride)
            + ", handle=" + to_string(handle));
        return static_cast<jlong>(handle);
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return 0;
    }
}

extern "C" JNIEXPORT void JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_setRawMatrixPayloadBlock
    (JNIEnv *env, jclass, jlong raw_matrix_handle, jint payload_block_index, jlongArray storage_block_array,
     jint bff_slot_num, jbyteArray params_bytes) {
    jlong *storage_elements = nullptr;
    try {
        if (payload_block_index < 0 || bff_slot_num <= 0) {
            throw invalid_argument("invalid FUSE_PIR_C raw matrix payload block metadata");
        }
        fusepirc::CircuitBootstrapParams params = deserialize_circuit_bootstrap_params(
            jbyte_array_to_vector(env, params_bytes)
        );
        shared_ptr<FusePirCRawEncodedMatrix> matrix = get_raw_matrix(static_cast<uint64_t>(raw_matrix_handle));
        if (static_cast<uint32_t>(payload_block_index) >= matrix->payloadBlockNum) {
            throw invalid_argument("FUSE_PIR_C raw matrix payload block index out of range");
        }
        if (env->GetArrayLength(storage_block_array) != bff_slot_num) {
            throw invalid_argument("FUSE_PIR_C raw matrix storage block dimension mismatch");
        }
        if (static_cast<uint64_t>(matrix->rowNum) * static_cast<uint64_t>(matrix->colNum)
            < static_cast<uint64_t>(bff_slot_num)) {
            throw invalid_argument("FUSE_PIR_C raw matrix BFF slot count exceeds matrix shape");
        }
        storage_elements = env->GetLongArrayElements(storage_block_array, nullptr);
        if (storage_elements == nullptr) {
            throw runtime_error("failed to access FUSE_PIR_C raw matrix storage block");
        }
        uint32_t p = static_cast<uint32_t>(payload_block_index);
        uint32_t packed_group = p / matrix->blocksPerPackedMatrix;
        uint32_t local_block = p % matrix->blocksPerPackedMatrix;
        for (uint32_t slot = 0; slot < static_cast<uint32_t>(bff_slot_num); slot++) {
            if (storage_elements[slot] < 0) {
                throw invalid_argument("negative FUSE_PIR_C BFF storage value");
            }
            uint32_t row = slot % matrix->rowNum;
            uint32_t col = slot / matrix->rowNum;
            if (col >= matrix->colNum) {
                throw invalid_argument("FUSE_PIR_C BFF storage slot exceeds matrix shape");
            }
            uint32_t coeff_index = row * matrix->blocksPerPackedMatrix + local_block;
            if (packed_group >= matrix->packedMatrixGroupNum || coeff_index >= params.degree) {
                throw invalid_argument("FUSE_PIR_C BFF packed coefficient index exceeds raw RLWE degree");
            }
            uint64_t value = static_cast<uint64_t>(storage_elements[slot]) % params.modulus;
            matrix->columns[packed_group][col].coeffs[coeff_index] = value;
        }
        matrix->decomposedColumns.clear();
        env->ReleaseLongArrayElements(storage_block_array, storage_elements, JNI_ABORT);
    } catch (const exception &e) {
        if (storage_elements != nullptr) {
            env->ReleaseLongArrayElements(storage_block_array, storage_elements, JNI_ABORT);
        }
        throw_runtime(env, e.what());
    }
}

extern "C" JNIEXPORT void JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_finalizeRawMatrix
    (JNIEnv *env, jclass, jlong raw_matrix_handle, jbyteArray params_bytes) {
    try {
        auto total_start = Clock::now();
        fusepirc::CircuitBootstrapParams params = deserialize_circuit_bootstrap_params(
            jbyte_array_to_vector(env, params_bytes)
        );
        shared_ptr<FusePirCRawEncodedMatrix> matrix = get_raw_matrix(static_cast<uint64_t>(raw_matrix_handle));
        validate_raw_encoded_matrix(*matrix, params.rlweParams);
        auto step_start = Clock::now();
        cache_raw_matrix_column_decomposition(*matrix, params.gadgetParams);
        perf_log("server.init.rawMatrixHandle.finalize_column_decomposition_cache_ms="
            + to_string(elapsed_ms(step_start))
            + ", total_ms=" + to_string(elapsed_ms(total_start)));
    } catch (const exception &e) {
        throw_runtime(env, e.what());
    }
}

extern "C" JNIEXPORT void JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_destroyRawMatrix
    (JNIEnv *, jclass, jlong handle) {
    unregister_raw_matrix(static_cast<uint64_t>(handle));
}

extern "C" JNIEXPORT jbyteArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_generateReply___3BJ_3BJ
    (JNIEnv *env, jclass, jbyteArray compressed_query_bytes, jlong eval_key_handle, jbyteArray params_bytes,
     jlong raw_matrix_handle) {
    try {
        auto total_start = Clock::now();
        auto step_start = Clock::now();
        fusepirc::CircuitBootstrapParams params = deserialize_circuit_bootstrap_params(
            jbyte_array_to_vector(env, params_bytes)
        );
        perf_log("generateReply.parse_params_ms=" + to_string(elapsed_ms(step_start)));
        step_start = Clock::now();
        shared_ptr<fusepirc::CachedCircuitBootstrapEvaluationKey> evaluation_key =
            get_evaluation_key(static_cast<uint64_t>(eval_key_handle));
        shared_ptr<FusePirCRawEncodedMatrix> matrix = get_raw_matrix(static_cast<uint64_t>(raw_matrix_handle));
        perf_log("generateReply.handle_lookup_ms=" + to_string(elapsed_ms(step_start))
            + ", raw_matrix_deserialize_ms=0");
        step_start = Clock::now();
        fusepirc::CompressedLweBits query = fusepirc::deserialize_compressed_lwe_bits(
            jbyte_array_to_vector(env, compressed_query_bytes)
        );
        perf_log("generateReply.query_parse_ms=" + to_string(elapsed_ms(step_start)));
        step_start = Clock::now();
        vector<fusepirc::RawRlweCipher> response = generate_fusepirc_raw_reply(
            query, *evaluation_key, params, *matrix
        );
        uint64_t raw_reply_ms = elapsed_ms(step_start);
        step_start = Clock::now();
        vector<uint8_t> serialized = serialize_raw_rlwe_cipher_vector(
            response, matrix->payloadBlockNum, matrix->blocksPerPackedMatrix, matrix->packedMatrixGroupNum);
        perf_log("generateReply.response_serialization_ms=" + to_string(elapsed_ms(step_start))
            + ", responseBytes=" + to_string(serialized.size())
            + ", raw_reply_ms=" + to_string(raw_reply_ms)
            + ", total_ms=" + to_string(elapsed_ms(total_start)));
        return vector_to_jbyte_array(env, serialized);
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

extern "C" JNIEXPORT jbyteArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_generateReply___3BJ_3B_3B
    (JNIEnv *env, jclass, jbyteArray compressed_query_bytes, jlong eval_key_handle, jbyteArray params_bytes,
     jbyteArray raw_matrix_bytes) {
    try {
        auto total_start = Clock::now();
        perf_log("generateReply.byteArrayMatrixPath=deprecated_formal_server_uses_handle");
        auto step_start = Clock::now();
        fusepirc::CircuitBootstrapParams params = deserialize_circuit_bootstrap_params(
            jbyte_array_to_vector(env, params_bytes)
        );
        perf_log("generateReply.parse_params_ms=" + to_string(elapsed_ms(step_start)));
        step_start = Clock::now();
        shared_ptr<fusepirc::CachedCircuitBootstrapEvaluationKey> evaluation_key =
            get_evaluation_key(static_cast<uint64_t>(eval_key_handle));
        perf_log("generateReply.eval_key_lookup_ms=" + to_string(elapsed_ms(step_start)));
        step_start = Clock::now();
        fusepirc::CompressedLweBits query = fusepirc::deserialize_compressed_lwe_bits(
            jbyte_array_to_vector(env, compressed_query_bytes)
        );
        perf_log("generateReply.query_parse_ms=" + to_string(elapsed_ms(step_start)));
        step_start = Clock::now();
        FusePirCRawEncodedMatrix matrix = deserialize_raw_encoded_matrix(
            jbyte_array_to_vector(env, raw_matrix_bytes), params.rlweParams
        );
        perf_log("generateReply.raw_matrix_deserialize_ms=" + to_string(elapsed_ms(step_start))
            + ", rawMatrixBytes=" + to_string(env->GetArrayLength(raw_matrix_bytes)));
        step_start = Clock::now();
        vector<fusepirc::RawRlweCipher> response = generate_fusepirc_raw_reply(
            query, *evaluation_key, params, matrix
        );
        uint64_t raw_reply_ms = elapsed_ms(step_start);
        step_start = Clock::now();
        vector<uint8_t> serialized = serialize_raw_rlwe_cipher_vector(
            response, matrix.payloadBlockNum, matrix.blocksPerPackedMatrix, matrix.packedMatrixGroupNum);
        perf_log("generateReply.response_serialization_ms=" + to_string(elapsed_ms(step_start))
            + ", responseBytes=" + to_string(serialized.size())
            + ", raw_reply_ms=" + to_string(raw_reply_ms)
            + ", total_ms=" + to_string(elapsed_ms(total_start)));
        return vector_to_jbyte_array(env, serialized);
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

extern "C" JNIEXPORT jboolean JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_checkRawReplyForCheck
    (JNIEnv *env, jclass, jbyteArray raw_response_bytes, jbyteArray client_secret_bytes, jbyteArray params_bytes) {
    try {
        fusepirc::CircuitBootstrapParams params = deserialize_circuit_bootstrap_params(
            jbyte_array_to_vector(env, params_bytes)
        );
        fusepirc::CircuitBootstrapClientSecretState client_secret = deserialize_circuit_bootstrap_client_secret(
            jbyte_array_to_vector(env, client_secret_bytes)
        );
        vector<fusepirc::RawRlweCipher> response = deserialize_raw_rlwe_cipher_vector(
            jbyte_array_to_vector(env, raw_response_bytes)
        );
        if (response.size() != 1 || client_secret.rlweSk.s.degree != params.degree
            || client_secret.rlweSk.s.modulus != params.modulus) {
            return false;
        }
        fusepirc::TorusPoly phase = fusepirc::raw_rlwe_decrypt_phase(response[0], client_secret.rlweSk);
        return centered_distance(phase.coeffs[0], 6, params.modulus) <= 12000;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return false;
    }
}

extern "C" JNIEXPORT jlongArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_decryptRawResponse
    (JNIEnv *env, jclass, jbyteArray raw_response_bytes, jbyteArray client_secret_bytes, jbyteArray params_bytes) {
    try {
        fusepirc::CircuitBootstrapParams params = deserialize_circuit_bootstrap_params(
            jbyte_array_to_vector(env, params_bytes)
        );
        fusepirc::CircuitBootstrapClientSecretState client_secret = deserialize_circuit_bootstrap_client_secret(
            jbyte_array_to_vector(env, client_secret_bytes)
        );
        FusePirCRawResponse response = deserialize_raw_response(jbyte_array_to_vector(env, raw_response_bytes));
        if (response.blocks.size() != response.packedMatrixGroupNum) {
            throw invalid_argument("raw response packed group count mismatch");
        }
        jlongArray result = env->NewLongArray(static_cast<jsize>(response.payloadBlockNum));
        vector<jlong> values(response.payloadBlockNum);
        for (uint32_t group = 0; group < response.blocks.size(); group++) {
            if (response.blocks[group].params.degree != params.degree
                || response.blocks[group].params.modulus != params.modulus
                || client_secret.rlweSk.s.degree != params.degree
                || client_secret.rlweSk.s.modulus != params.modulus) {
                throw invalid_argument("raw response decrypt params mismatch");
            }
            fusepirc::TorusPoly phase = fusepirc::raw_rlwe_decrypt_phase(response.blocks[group], client_secret.rlweSk);
            for (uint32_t local_block = 0; local_block < response.blocksPerPackedMatrix; local_block++) {
                uint32_t payload_index = group * response.blocksPerPackedMatrix + local_block;
                if (payload_index >= response.payloadBlockNum) {
                    break;
                }
                if (local_block >= phase.degree) {
                    throw invalid_argument("raw response local block coefficient out of range");
                }
                values[payload_index] =
                    static_cast<jlong>(decode_payload_from_raw_torus(phase.coeffs[local_block], params.modulus));
                perf_log("client.decrypt_raw_response"
                    + string(", group=") + to_string(group)
                    + ", localBlock=" + to_string(local_block)
                    + ", payloadIndex=" + to_string(payload_index)
                    + ", coeff=" + to_string(phase.coeffs[local_block])
                    + ", decoded=" + to_string(values[payload_index])
                    + ", payloadScale=" + to_string(fusepirc_payload_scale(params.modulus)));
            }
        }
        env->SetLongArrayRegion(result, 0, static_cast<jsize>(values.size()), values.data());
        return result;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

extern "C" JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_generateReply___3B_3B_3BLjava_util_List_2IIIILedu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCCircuitBootstrapParams_2
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray pk_bytes, jbyteArray compressed_query_bytes, jobject,
     jint, jint, jint, jint, jobject circuit_bootstrap_params_obj) {
    try {
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "FUSE_PIR_C", __func__);
        PublicKey public_key = deserialize_public_key(env, pk_bytes, context);
        fusepirc::CompressedLweBits compressed_query = fusepirc::deserialize_compressed_lwe_bits(
            jbyte_array_to_vector(env, compressed_query_bytes)
        );
        vector<fusepirc::LweCipher> lwe_bits = fusepirc::recover_lwe_bits_from_compressed_query(compressed_query);
        if (lwe_bits.empty()) {
            throw invalid_argument("empty FUSE_PIR_C compressed query");
        }
        fusepirc::LweParams lwe_params{};
        lwe_params.n = compressed_query.lwe_dimension;
        lwe_params.q = compressed_query.q;
        lwe_params.sigma = 1.0;
        lwe_params.delta = compressed_query.q / 2;
        (void) public_key;
        (void) lwe_params;
        (void) circuit_bootstrap_params_obj;
        throw logic_error(BOOTSTRAP_NOT_IMPLEMENTED);
    } catch (const logic_error &e) {
        if (string(e.what()) == BOOTSTRAP_NOT_IMPLEMENTED) {
            throw_unsupported(env, e.what());
        } else {
            throw_runtime(env, e.what());
        }
        return nullptr;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jobjectArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepirc_FusePirCStdKwPirNativeUtils_decryptReply
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray sk_bytes, jobject response) {
    try {
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "FUSE_PIR_C", __func__);
        SecretKey secret_key = deserialize_secret_key(env, sk_bytes, context);
        vector<Ciphertext> replies = deserialize_ciphertexts(env, response, context);
        Decryptor decryptor(context, secret_key);
        uint32_t coeff_count = parms.poly_modulus_degree();
        jclass long_array_cls = env->FindClass("[J");
        jobjectArray result = env->NewObjectArray(static_cast<jsize>(replies.size()), long_array_cls, nullptr);
        env->DeleteLocalRef(long_array_cls);
        for (jsize i = 0; i < static_cast<jsize>(replies.size()); i++) {
            if (replies[i].is_ntt_form()) {
                Evaluator evaluator(context);
                evaluator.transform_from_ntt_inplace(replies[i]);
            }
            Plaintext plain(coeff_count);
            decryptor.decrypt(replies[i], plain);
            jlongArray row = env->NewLongArray(static_cast<jsize>(coeff_count));
            vector<jlong> coeffs(coeff_count);
            for (uint32_t j = 0; j < coeff_count; j++) {
                coeffs[j] = j < plain.coeff_count() ? static_cast<jlong>(plain[j]) : 0L;
            }
            env->SetLongArrayRegion(row, 0, static_cast<jsize>(coeff_count), coeffs.data());
            env->SetObjectArrayElement(result, i, row);
            env->DeleteLocalRef(row);
        }
        return result;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}
