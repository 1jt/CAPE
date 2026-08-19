#include "edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils.h"
#include "seal/seal.h"
#include "../../serialize.h"
#include "../../index_pir.h"
#include "../../tfhe/tfhe.h"
#include "../../utils.h"
#include "seal/util/iterator.h"
#include "seal/util/polyarithsmallmod.h"
#include <algorithm>
#include <atomic>
#include <iostream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <unordered_map>

using namespace seal;
using namespace std;

struct CapeLweToRgswKeyHandle {
    vector<RGSWCipher> key;
    size_t poly_modulus_degree;
    size_t coeff_modulus_count;
    uint64_t plain_modulus;
    size_t item_count;
    uint64_t total_bytes;
};

static mutex g_cape_lwe_to_rgsw_key_mutex;
static unordered_map<long, unique_ptr<CapeLweToRgswKeyHandle>> g_cape_lwe_to_rgsw_key_registry;
static atomic<long> g_next_cape_lwe_to_rgsw_key_handle{1};

static void throw_runtime(JNIEnv *env, const char *message) {
    jclass exception = env->FindClass("java/lang/RuntimeException");
    if (exception != nullptr) {
        env->ThrowNew(exception, message);
        env->DeleteLocalRef(exception);
    }
}

static void throw_unsupported(JNIEnv *env, const char *message) {
    jclass exception = env->FindClass("java/lang/UnsupportedOperationException");
    if (exception != nullptr) {
        env->ThrowNew(exception, message);
        env->DeleteLocalRef(exception);
    }
}

static void require_non_null(jobject object, const char *name) {
    if (object == nullptr) {
        throw invalid_argument(string(name) + " must not be null");
    }
}

static jobject new_array_list(JNIEnv *env) {
    jclass list_class = env->FindClass("java/util/ArrayList");
    jmethodID list_init = env->GetMethodID(list_class, "<init>", "()V");
    jobject list = env->NewObject(list_class, list_init);
    env->DeleteLocalRef(list_class);
    return list;
}

static void list_add(JNIEnv *env, jobject list, jobject element) {
    jclass list_class = env->FindClass("java/util/List");
    jmethodID add = env->GetMethodID(list_class, "add", "(Ljava/lang/Object;)Z");
    env->CallBooleanMethod(list, add, element);
    env->DeleteLocalRef(list_class);
}

static vector<int> jint_array_to_vector(JNIEnv *env, jintArray array) {
    jint length = env->GetArrayLength(array);
    jint *ptr = env->GetIntArrayElements(array, JNI_FALSE);
    vector<int> result(ptr, ptr + length);
    env->ReleaseIntArrayElements(array, ptr, 0);
    return result;
}

static jbyteArray bytes_from_string(JNIEnv *env, const string &data) {
    auto out = env->NewByteArray(static_cast<jsize>(data.size()));
    env->SetByteArrayRegion(out, 0, static_cast<jsize>(data.size()),
                            reinterpret_cast<const jbyte *>(data.data()));
    return out;
}

static string string_from_bytes(JNIEnv *env, jbyteArray bytes) {
    require_non_null(bytes, "byte array");
    jbyte *data = env->GetByteArrayElements(bytes, nullptr);
    if (data == nullptr) {
        throw invalid_argument("GetByteArrayElements returned null");
    }
    string result(reinterpret_cast<char *>(data), env->GetArrayLength(bytes));
    env->ReleaseByteArrayElements(bytes, data, JNI_ABORT);
    return result;
}

static jbyteArray serialize_rgsw(JNIEnv *env, const RGSWCipher &cipher) {
    ostringstream output;
    uint32_t size = static_cast<uint32_t>(cipher.size());
    output.write(reinterpret_cast<const char *>(&size), sizeof(size));
    for (const auto &ct : cipher) {
        ostringstream ct_output;
        ct.save(ct_output, Serialization::compr_mode_default);
        string ct_bytes = ct_output.str();
        uint32_t ct_size = static_cast<uint32_t>(ct_bytes.size());
        output.write(reinterpret_cast<const char *>(&ct_size), sizeof(ct_size));
        output.write(ct_bytes.data(), static_cast<streamsize>(ct_bytes.size()));
    }
    return bytes_from_string(env, output.str());
}

static RGSWCipher deserialize_rgsw(JNIEnv *env, jbyteArray bytes, const SEALContext &context) {
    string data = string_from_bytes(env, bytes);
    istringstream input(data);
    uint32_t size;
    input.read(reinterpret_cast<char *>(&size), sizeof(size));
    RGSWCipher result;
    result.reserve(size);
    for (uint32_t i = 0; i < size; i++) {
        uint32_t ct_size;
        input.read(reinterpret_cast<char *>(&ct_size), sizeof(ct_size));
        string ct_bytes(ct_size, '\0');
        input.read(ct_bytes.data(), static_cast<streamsize>(ct_size));
        istringstream ct_input(ct_bytes);
        Ciphertext ct;
        ct.load(context, ct_input);
        result.emplace_back(std::move(ct));
    }
    return result;
}

static Plaintext rns_bit_plaintext(const SEALContext &context, uint64_t bit) {
    auto &parms = context.first_context_data()->parms();
    uint32_t coeff_count = parms.poly_modulus_degree();
    uint32_t coeff_mod_count = parms.coeff_modulus().size();
    Plaintext plain(coeff_count * coeff_mod_count);
    plain.resize(coeff_count * coeff_mod_count);
    fill(plain.data(), plain.data() + coeff_count * coeff_mod_count, 0);
    for (uint32_t i = 0; i < coeff_mod_count; i++) {
        plain[i * coeff_count] = bit;
    }
    auto plain_iter = util::RNSIter(plain.data(), coeff_count);
    util::ntt_negacyclic_harvey(plain_iter, coeff_mod_count, context.first_context_data()->small_ntt_tables());
    return plain;
}

static void scalar_multiply_ciphertext_inplace(Ciphertext &ct, uint64_t scalar, const SEALContext &context) {
    auto &parms = context.first_context_data()->parms();
    size_t coeff_count = parms.poly_modulus_degree();
    size_t coeff_mod_count = parms.coeff_modulus().size();
    const auto &coeff_modulus = parms.coeff_modulus();
    for (size_t poly = 0; poly < ct.size(); poly++) {
        for (size_t mod_index = 0; mod_index < coeff_mod_count; mod_index++) {
            uint64_t reduced_scalar = util::barrett_reduce_64(scalar, coeff_modulus[mod_index]);
            util::multiply_poly_scalar_coeffmod(
                ct.data(poly) + mod_index * coeff_count, coeff_count, reduced_scalar,
                coeff_modulus[mod_index], ct.data(poly) + mod_index * coeff_count
            );
        }
    }
}

static RGSWCipher scalar_multiply_rgsw(const RGSWCipher &cipher, uint64_t scalar, const SEALContext &context) {
    RGSWCipher result = cipher;
    for (auto &ct : result) {
        scalar_multiply_ciphertext_inplace(ct, scalar, context);
    }
    return result;
}

static void sub_rgsw_inplace(RGSWCipher &left, const RGSWCipher &right, Evaluator &evaluator) {
    if (left.size() != right.size()) {
        throw invalid_argument("RGSW size mismatch");
    }
    for (size_t i = 0; i < left.size(); i++) {
        evaluator.sub_inplace(left[i], right[i]);
    }
}

static vector<vector<uint64_t>> deserialize_long_matrix(JNIEnv *env, jobjectArray matrix) {
    jsize row_num = env->GetArrayLength(matrix);
    vector<vector<uint64_t>> result(static_cast<size_t>(row_num));
    for (jsize row = 0; row < row_num; row++) {
        auto row_array = reinterpret_cast<jlongArray>(env->GetObjectArrayElement(matrix, row));
        jsize col_num = env->GetArrayLength(row_array);
        jlong *data = env->GetLongArrayElements(row_array, nullptr);
        result[static_cast<size_t>(row)].resize(static_cast<size_t>(col_num));
        for (jsize col = 0; col < col_num; col++) {
            result[static_cast<size_t>(row)][static_cast<size_t>(col)] = static_cast<uint64_t>(data[col]);
        }
        env->ReleaseLongArrayElements(row_array, data, JNI_ABORT);
        env->DeleteLocalRef(row_array);
    }
    return result;
}

static vector<uint64_t> jlong_array_to_u64_vector(JNIEnv *env, jlongArray array) {
    jsize length = env->GetArrayLength(array);
    jlong *data = env->GetLongArrayElements(array, nullptr);
    vector<uint64_t> result(static_cast<size_t>(length));
    for (jsize i = 0; i < length; i++) {
        result[static_cast<size_t>(i)] = static_cast<uint64_t>(data[i]);
    }
    env->ReleaseLongArrayElements(array, data, JNI_ABORT);
    return result;
}

static uint32_t ceil_log2(uint32_t n) {
    uint32_t log = 0;
    uint32_t pow = 1;
    while (pow < n) {
        pow <<= 1;
        log++;
    }
    return log;
}

static uint64_t inverse_mod(uint64_t value, uint64_t modulus) {
    int64_t t = 0;
    int64_t new_t = 1;
    int64_t r = static_cast<int64_t>(modulus);
    int64_t new_r = static_cast<int64_t>(value % modulus);
    while (new_r != 0) {
        int64_t quotient = r / new_r;
        int64_t next_t = t - quotient * new_t;
        t = new_t;
        new_t = next_t;
        int64_t next_r = r - quotient * new_r;
        r = new_r;
        new_r = next_r;
    }
    if (r != 1) {
        throw invalid_argument("value is not invertible modulo plaintext modulus");
    }
    if (t < 0) {
        t += static_cast<int64_t>(modulus);
    }
    return static_cast<uint64_t>(t);
}

static void keep_constant_coefficient_inplace(Evaluator &evaluator, Ciphertext &ciphertext,
                                              const GaloisKeys &galois_keys, const SEALContext &context) {
    const auto &parms = context.first_context_data()->parms();
    size_t coeff_count = parms.poly_modulus_degree();
    for (size_t stride = coeff_count / 2; stride >= 1; stride >>= 1) {
        Ciphertext folded;
        evaluator.apply_galois(ciphertext, static_cast<uint32_t>(2 * stride + 1), galois_keys, folded);
        evaluator.add_inplace(ciphertext, folded);
        if (stride == 1) {
            break;
        }
    }
}

static vector<uint32_t> get_cape_galois_elts(const SEALContext &context) {
    const auto *galois_tool = context.key_context_data()->galois_tool();
    vector<uint32_t> galois_elts = galois_tool->get_elts_all();
    size_t coeff_count = context.key_context_data()->parms().poly_modulus_degree();
    for (size_t stride = coeff_count / 2; stride >= 1; stride >>= 1) {
        galois_elts.push_back(static_cast<uint32_t>(2 * stride + 1));
        if (stride == 1) {
            break;
        }
    }
    sort(galois_elts.begin(), galois_elts.end());
    galois_elts.erase(unique(galois_elts.begin(), galois_elts.end()), galois_elts.end());
    return galois_elts;
}

static jobject list_get(JNIEnv *env, jobject list, jint index) {
    require_non_null(list, "list");
    jclass list_class = env->FindClass("java/util/List");
    jmethodID get = env->GetMethodID(list_class, "get", "(I)Ljava/lang/Object;");
    jobject item = env->CallObjectMethod(list, get, index);
    env->DeleteLocalRef(list_class);
    return item;
}

static jint list_size(JNIEnv *env, jobject list) {
    require_non_null(list, "list");
    jclass list_class = env->FindClass("java/util/List");
    jmethodID size = env->GetMethodID(list_class, "size", "()I");
    jint result = env->CallIntMethod(list, size);
    env->DeleteLocalRef(list_class);
    return result;
}

static Plaintext deserialize_plaintext_from_list(JNIEnv *env, jobject list, jint index, const SEALContext &context) {
    auto item = reinterpret_cast<jbyteArray>(list_get(env, list, index));
    string data = string_from_bytes(env, item);
    env->DeleteLocalRef(item);
    Plaintext result;
    istringstream input(data);
    result.load(context, input);
    return result;
}

static void check_lwe_to_rgsw_key_handle_params(const CapeLweToRgswKeyHandle &handle,
                                                const EncryptionParameters &parms) {
    if (handle.poly_modulus_degree != parms.poly_modulus_degree()
        || handle.coeff_modulus_count != parms.coeff_modulus().size()
        || handle.plain_modulus != parms.plain_modulus().value()) {
        throw invalid_argument("CAPE LWE-to-RGSW key handle parameter mismatch");
    }
}

static Ciphertext mul_by_monomial(const Ciphertext &ct, int exponent, const SEALContext &context) {
    auto n = static_cast<int>(context.first_context_data()->parms().poly_modulus_degree());
    int modulus = 2 * n;
    int normalized = exponent % modulus;
    if (normalized < 0) {
        normalized += modulus;
    }
    Ciphertext out;
    multiply_power_of_X(ct, out, static_cast<uint32_t>(normalized), context);
    return out;
}

static Ciphertext cmux(const RGSWCipher &gsw_bit, const Ciphertext &ct1, const Ciphertext &ct0,
                       TFHEcipher &tfhe, Evaluator &evaluator, const SEALContext &context) {
    Ciphertext diff = ct1;
    evaluator.sub_inplace(diff, ct0);
    if (diff.is_transparent()) {
        return ct0;
    }
    if (diff.is_ntt_form()) {
        evaluator.transform_from_ntt_inplace(diff);
    }
    Ciphertext selected(context);
    selected.resize(context, context.first_context_data()->parms_id(), 2);
    auto &parms = context.first_context_data()->parms();
    size_t coeff_count = parms.poly_modulus_degree();
    size_t coeff_mod_count = parms.coeff_modulus().size();
    for (size_t poly = 0; poly < selected.size(); poly++) {
        fill(selected.data(poly), selected.data(poly) + coeff_count * coeff_mod_count, 0);
    }
    selected.is_ntt_form() = true;
    tfhe.ExternalProduct(selected, diff, gsw_bit);
    if (selected.is_transparent()) {
        return ct0;
    }
    if (ct0.is_ntt_form()) {
        evaluator.add_inplace(selected, ct0);
        return selected;
    } else {
        evaluator.transform_from_ntt_inplace(selected);
        evaluator.add_inplace(selected, ct0);
        return selected;
    }
}

static Ciphertext blind_rotate_to_zero(const Ciphertext &packed_column, const vector<RGSWCipher> &encrypted_row_bits,
                                       int row_num, int row_stride, const SEALContext &context, TFHEcipher &tfhe,
                                       Evaluator &evaluator) {
    Ciphertext current = packed_column;
    uint32_t bit_num = ceil_log2(static_cast<uint32_t>(row_num));
    if (encrypted_row_bits.size() < bit_num) {
        throw invalid_argument("not enough encrypted row bits");
    }
    for (uint32_t j = 0; j < bit_num; j++) {
        Ciphertext shifted = mul_by_monomial(current, -static_cast<int>((1U << j) * row_stride), context);
        current = cmux(encrypted_row_bits[j], shifted, current, tfhe, evaluator, context);
    }
    return current;
}

static vector<vector<vector<uint64_t>>> deserialize_matrices(JNIEnv *env, jobjectArray matrices) {
    jsize group_num = env->GetArrayLength(matrices);
    vector<vector<vector<uint64_t>>> result(group_num);
    for (jsize g = 0; g < group_num; g++) {
        auto rows = reinterpret_cast<jobjectArray>(env->GetObjectArrayElement(matrices, g));
        jsize row_num = env->GetArrayLength(rows);
        result[g].resize(row_num);
        for (jsize r = 0; r < row_num; r++) {
            auto cols = reinterpret_cast<jlongArray>(env->GetObjectArrayElement(rows, r));
            jsize col_num = env->GetArrayLength(cols);
            jlong *col_data = env->GetLongArrayElements(cols, nullptr);
            result[g][r].resize(col_num);
            for (jsize c = 0; c < col_num; c++) {
                result[g][r][c] = static_cast<uint64_t>(col_data[c]);
            }
            env->ReleaseLongArrayElements(cols, col_data, JNI_ABORT);
            env->DeleteLocalRef(cols);
        }
        env->DeleteLocalRef(rows);
    }
    return result;
}

static Plaintext build_shifted_matrix_row(const Plaintext &raw_row, const EncryptionParameters &parms,
                                          int col_num, int blocks_per_packed_matrix) {
    uint32_t coeff_count = parms.poly_modulus_degree();
    Plaintext plain(coeff_count);
    plain.set_zero();
    for (jint col = 0; col < col_num; col++) {
        for (jint block_offset = 0; block_offset < blocks_per_packed_matrix; block_offset++) {
            size_t raw_index = static_cast<size_t>(col * blocks_per_packed_matrix + block_offset);
            if (raw_index >= raw_row.coeff_count()) {
                continue;
            }
            uint64_t raw = raw_row[raw_index];
            if (raw == 0) {
                continue;
            }
            uint64_t value = raw % parms.plain_modulus().value();
            int exponent = block_offset - col * blocks_per_packed_matrix;
            if (exponent >= 0) {
                plain[static_cast<size_t>(exponent)] = value;
            } else {
                plain[static_cast<size_t>(static_cast<int>(coeff_count) + exponent)]
                    = (parms.plain_modulus().value() - value) % parms.plain_modulus().value();
            }
        }
    }
    return plain;
}

static Plaintext build_shifted_matrix_row_with_query_stride(const Plaintext &raw_row,
                                                            const EncryptionParameters &parms,
                                                            int col_num,
                                                            int matrix_col_offset,
                                                            int matrix_blocks_per_packed_matrix,
                                                            int query_blocks_per_packed_matrix) {
    uint32_t coeff_count = parms.poly_modulus_degree();
    Plaintext plain(coeff_count);
    plain.set_zero();
    for (jint col = 0; col < col_num; col++) {
        for (jint block_offset = 0; block_offset < matrix_blocks_per_packed_matrix; block_offset++) {
            size_t raw_index = static_cast<size_t>(col * matrix_blocks_per_packed_matrix + block_offset);
            if (raw_index >= raw_row.coeff_count()) {
                continue;
            }
            uint64_t raw = raw_row[raw_index];
            if (raw == 0) {
                continue;
            }
            uint64_t value = raw % parms.plain_modulus().value();
            int exponent = block_offset - (matrix_col_offset + col) * query_blocks_per_packed_matrix;
            exponent %= static_cast<int>(coeff_count);
            if (exponent < 0) {
                exponent += static_cast<int>(coeff_count);
                value = (parms.plain_modulus().value() - value) % parms.plain_modulus().value();
            }
            plain[static_cast<size_t>(exponent)] = value;
        }
    }
    return plain;
}

static Ciphertext extract_packed_query_bloom_group(Evaluator &evaluator,
                                                   const GaloisKeys &galois_keys,
                                                   const vector<Ciphertext> &packed_bloom_queries,
                                                   const SEALContext &context,
                                                   int group_start_bit,
                                                   int group_block_num,
                                                   int bloom_bit_length) {
    const auto &parms = context.first_context_data()->parms();
    int coeff_count = static_cast<int>(parms.poly_modulus_degree());
    if (group_start_bit < 0 || group_start_bit >= bloom_bit_length) {
        throw invalid_argument("invalid CAPE packed query Bloom group start");
    }
    uint64_t inverse_coeff_count = inverse_mod(
        static_cast<uint64_t>(coeff_count) % parms.plain_modulus().value(), parms.plain_modulus().value()
    );
    Ciphertext group_query;
    bool initialized = false;
    for (int offset = 0; offset < group_block_num; offset++) {
        int bit_index = group_start_bit + offset;
        if (bit_index >= bloom_bit_length) {
            break;
        }
        int query_index = bit_index / coeff_count;
        int local_bit_index = bit_index % coeff_count;
        if (query_index < 0 || static_cast<size_t>(query_index) >= packed_bloom_queries.size()) {
            throw invalid_argument("CAPE packed query Bloom index out of range");
        }
        /*
         * Packed query Bloom ciphertexts use the same coefficient-domain inner-product encoding as the old group
         * queries: q[0] is stored at coeff 0, and q[i] is stored as -q[i] at coeff N-i. Extract q[bit_index] as a
         * positive constant first, divide out the coefficient-folding factor N, then place it back into the old local
         * group encoding position. This keeps the uploaded query packed while preserving the scalar Bloom payload score
         * semantics.
         */
        Ciphertext bit_query = local_bit_index == 0
            ? packed_bloom_queries[static_cast<size_t>(query_index)]
            : mul_by_monomial(packed_bloom_queries[static_cast<size_t>(query_index)], local_bit_index, context);
        keep_constant_coefficient_inplace(evaluator, bit_query, galois_keys, context);
        scalar_multiply_ciphertext_inplace(bit_query, inverse_coeff_count, context);
        if (offset > 0) {
            bit_query = mul_by_monomial(bit_query, -offset, context);
        }
        if (!initialized) {
            group_query = bit_query;
            initialized = true;
        } else if (!bit_query.is_transparent()) {
            evaluator.add_inplace(group_query, bit_query);
        }
    }
    if (!initialized) {
        throw invalid_argument("CAPE packed query Bloom group is empty");
    }
    return group_query;
}

static Plaintext encode_slots(JNIEnv *env, jlongArray values, const SEALContext &context) {
    BatchEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    jint length = env->GetArrayLength(values);
    if (static_cast<size_t>(length) > slot_count) {
        throw invalid_argument("slot vector length exceeds BatchEncoder slot count");
    }
    jlong *ptr = env->GetLongArrayElements(values, JNI_FALSE);
    vector<uint64_t> slots(slot_count, 0);
    for (jint i = 0; i < length; i++) {
        slots[static_cast<size_t>(i)] = static_cast<uint64_t>(ptr[i]);
    }
    env->ReleaseLongArrayElements(values, ptr, 0);
    Plaintext plaintext;
    encoder.encode(slots, plaintext);
    return plaintext;
}

static vector<Plaintext> encode_slot_chunks(JNIEnv *env, jlongArray values, const SEALContext &context) {
    BatchEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    jint length = env->GetArrayLength(values);
    jlong *ptr = env->GetLongArrayElements(values, JNI_FALSE);
    size_t chunk_num = (static_cast<size_t>(length) + slot_count - 1) / slot_count;
    vector<Plaintext> plaintexts;
    plaintexts.reserve(chunk_num);
    for (size_t chunk = 0; chunk < chunk_num; chunk++) {
        vector<uint64_t> slots(slot_count, 0ULL);
        size_t offset = chunk * slot_count;
        size_t chunk_size = min(slot_count, static_cast<size_t>(length) - offset);
        for (size_t i = 0; i < chunk_size; i++) {
            slots[i] = static_cast<uint64_t>(ptr[offset + i]);
        }
        Plaintext plaintext;
        encoder.encode(slots, plaintext);
        plaintexts.push_back(plaintext);
    }
    env->ReleaseLongArrayElements(values, ptr, 0);
    return plaintexts;
}

static vector<Plaintext> encode_slot_plaintexts(JNIEnv *env, jobjectArray values, const SEALContext &context) {
    jint size = env->GetArrayLength(values);
    vector<Plaintext> plaintexts;
    for (jint i = 0; i < size; i++) {
        auto row = (jlongArray) env->GetObjectArrayElement(values, i);
        vector<Plaintext> chunks = encode_slot_chunks(env, row, context);
        plaintexts.insert(plaintexts.end(), chunks.begin(), chunks.end());
        env->DeleteLocalRef(row);
    }
    return plaintexts;
}

static void add_all_slots_inplace(Evaluator &evaluator, Ciphertext &ciphertext, const GaloisKeys &galois_keys,
                                  size_t slot_count) {
    size_t row_size = slot_count / 2;
    for (size_t l = 1; l < row_size; l <<= 1) {
        Ciphertext rotated;
        evaluator.rotate_rows(ciphertext, static_cast<int>(l), galois_keys, rotated);
        evaluator.add_inplace(ciphertext, rotated);
    }
    Ciphertext rotated_columns;
    evaluator.rotate_columns(ciphertext, galois_keys, rotated_columns);
    evaluator.add_inplace(ciphertext, rotated_columns);
}

JNIEXPORT jbyteArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generateEncryptionParams
    (JNIEnv *env, jclass, jint poly_modulus_degree, jlong plain_modulus, jintArray) {
    try {
        EncryptionParameters parms = create_default_bfv_parameters_128(
            static_cast<size_t>(poly_modulus_degree), static_cast<uint64_t>(plain_modulus)
        );
        SEALContext context = create_context_128(parms, "CAPE", __func__);
        log_bfv_parameter_summary("[CAPE-PARAM]", "CAPE", context, false);
        return serialize_encryption_parms(env, parms);
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_keyGen
    (JNIEnv *env, jclass, jbyteArray parms_bytes) {
    try {
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "CAPE", __func__);
        KeyGenerator key_gen(context);
        const SecretKey &secret_key = key_gen.secret_key();
        Serializable<PublicKey> public_key = key_gen.create_public_key();
        Serializable<RelinKeys> relin_keys = key_gen.create_relin_keys();
        Serializable<GaloisKeys> galois_keys = key_gen.create_galois_keys(get_cape_galois_elts(context));
        jobject list = new_array_list(env);
        jbyteArray sk_bytes = serialize_secret_key(env, secret_key);
        jbyteArray pk_bytes = serialize_public_key(env, public_key);
        jbyteArray relin_bytes = serialize_relin_keys(env, relin_keys);
        jbyteArray galois_bytes = serialize_galois_keys(env, galois_keys);
        list_add(env, list, sk_bytes);
        list_add(env, list, pk_bytes);
        list_add(env, list, relin_bytes);
        list_add(env, list, galois_bytes);
        env->DeleteLocalRef(sk_bytes);
        env->DeleteLocalRef(pk_bytes);
        env->DeleteLocalRef(relin_bytes);
        env->DeleteLocalRef(galois_bytes);
        return list;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jbyteArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generateColumnQuery
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray, jbyteArray sk_bytes, jint column_index, jint column_num) {
    try {
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "CAPE", __func__);
        SecretKey secret_key = deserialize_secret_key(env, sk_bytes, context);
        if (column_index < 0 || column_index >= column_num ||
            static_cast<size_t>(column_num) > parms.poly_modulus_degree()) {
            throw invalid_argument("invalid CAPE column index / column num");
        }
        Plaintext plain(parms.poly_modulus_degree());
        plain.set_zero();
        plain[static_cast<size_t>(column_index)] = 1;
        Encryptor encryptor(context, secret_key);
        Serializable<Ciphertext> query_cipher = encryptor.encrypt_symmetric(plain);
        return serialize_ciphertext(env, query_cipher);
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jbyteArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generatePackedColumnQuery
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray, jbyteArray sk_bytes, jint column_index, jint column_num,
     jint blocks_per_packed_matrix) {
    try {
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "CAPE", __func__);
        SecretKey secret_key = deserialize_secret_key(env, sk_bytes, context);
        if (column_index < 0 || column_index >= column_num || blocks_per_packed_matrix <= 0) {
            throw invalid_argument("invalid CAPE packed column query index / shape");
        }
        int exponent = column_index * blocks_per_packed_matrix;
        if (static_cast<size_t>(exponent) >= parms.poly_modulus_degree()) {
            throw invalid_argument("CAPE packed column query exponent exceeds polyModulusDegree");
        }
        Plaintext plain(parms.poly_modulus_degree());
        plain.set_zero();
        plain[static_cast<size_t>(exponent)] = 1;
        Encryptor encryptor(context, secret_key);
        Serializable<Ciphertext> query_cipher = encryptor.encrypt_symmetric(plain);
        return serialize_ciphertext(env, query_cipher);
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generateEncryptedRowBits
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray pk_bytes, jbyteArray, jint row_index, jint row_num) {
    try {
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "CAPE", __func__);
        PublicKey public_key = deserialize_public_key(env, pk_bytes, context);
        if (row_index < 0 || row_index >= row_num) {
            throw invalid_argument("invalid CAPE row index / row num");
        }
        TFHEcipher tfhe(context, public_key);
        jobject list = new_array_list(env);
        uint32_t bit_num = ceil_log2(static_cast<uint32_t>(row_num));
        for (uint32_t j = 0; j < bit_num; j++) {
            uint64_t bit = (static_cast<uint32_t>(row_index) >> j) & 1U;
            Plaintext bit_plain = rns_bit_plaintext(context, bit);
            RGSWCipher gsw_bit;
            tfhe.encrypt(bit_plain, gsw_bit);
            jbyteArray bit_bytes = serialize_rgsw(env, gsw_bit);
            list_add(env, list, bit_bytes);
            env->DeleteLocalRef(bit_bytes);
        }
        return list;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generateLweToRgswKey
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray pk_bytes, jlongArray lwe_secret_key) {
    try {
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "CAPE", __func__);
        PublicKey public_key = deserialize_public_key(env, pk_bytes, context);
        vector<uint64_t> secret_key = jlong_array_to_u64_vector(env, lwe_secret_key);
        TFHEcipher tfhe(context, public_key);
        jobject list = new_array_list(env);
        for (uint64_t secret_bit : secret_key) {
            if (secret_bit != 0 && secret_bit != 1) {
                throw invalid_argument("CAPE LWE secret key must be binary");
            }
            Plaintext bit_plain = rns_bit_plaintext(context, secret_bit);
            RGSWCipher gsw_bit;
            tfhe.encrypt(bit_plain, gsw_bit);
            jbyteArray bit_bytes = serialize_rgsw(env, gsw_bit);
            list_add(env, list, bit_bytes);
            env->DeleteLocalRef(bit_bytes);
        }
        return list;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jlong JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_createLweToRgswKeyHandle
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray pk_bytes, jobject serialized_lwe_to_rgsw_key) {
    try {
        require_non_null(parms_bytes, "encryption parameters");
        require_non_null(pk_bytes, "public key");
        require_non_null(serialized_lwe_to_rgsw_key, "serialized CAPE LWE-to-RGSW key");
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "CAPE", __func__);
        (void) deserialize_public_key(env, pk_bytes, context);
        jint key_size = list_size(env, serialized_lwe_to_rgsw_key);
        if (key_size <= 0) {
            throw invalid_argument("empty CAPE LWE-to-RGSW key");
        }
        auto parsed = make_unique<CapeLweToRgswKeyHandle>();
        parsed->key.reserve(static_cast<size_t>(key_size));
        parsed->poly_modulus_degree = parms.poly_modulus_degree();
        parsed->coeff_modulus_count = parms.coeff_modulus().size();
        parsed->plain_modulus = parms.plain_modulus().value();
        parsed->item_count = static_cast<size_t>(key_size);
        parsed->total_bytes = 0;
        for (jint i = 0; i < key_size; i++) {
            auto key_bytes = reinterpret_cast<jbyteArray>(list_get(env, serialized_lwe_to_rgsw_key, i));
            parsed->total_bytes += static_cast<uint64_t>(env->GetArrayLength(key_bytes));
            parsed->key.push_back(deserialize_rgsw(env, key_bytes, context));
            env->DeleteLocalRef(key_bytes);
        }
        long handle = g_next_cape_lwe_to_rgsw_key_handle.fetch_add(1);
        if (handle == 0) {
            handle = g_next_cape_lwe_to_rgsw_key_handle.fetch_add(1);
        }
        lock_guard<mutex> lock(g_cape_lwe_to_rgsw_key_mutex);
        g_cape_lwe_to_rgsw_key_registry.emplace(handle, move(parsed));
        return static_cast<jlong>(handle);
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return 0;
    }
}

JNIEXPORT void JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_destroyLweToRgswKeyHandle
    (JNIEnv *env, jclass, jlong handle) {
    try {
        if (handle == 0) {
            return;
        }
        lock_guard<mutex> lock(g_cape_lwe_to_rgsw_key_mutex);
        auto erased = g_cape_lwe_to_rgsw_key_registry.erase(static_cast<long>(handle));
        if (erased == 0) {
            cerr << "[CAPE-CHECKPOINT] native destroyLweToRgswKeyHandle missing handle="
                 << static_cast<long>(handle) << endl;
        }
    } catch (const exception &e) {
        throw_runtime(env, e.what());
    }
}

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_convertCompressedRowBitsToRgswWithHandle
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray pk_bytes, jlong handle,
     jobjectArray a_array, jlongArray b_array) {
    try {
        require_non_null(parms_bytes, "encryption parameters");
        require_non_null(pk_bytes, "public key");
        require_non_null(a_array, "compressed row-bit a array");
        require_non_null(b_array, "compressed row-bit b array");
        if (handle == 0) {
            throw invalid_argument("CAPE LWE-to-RGSW key handle is not initialized");
        }
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "CAPE", __func__);
        PublicKey public_key = deserialize_public_key(env, pk_bytes, context);
        Evaluator evaluator(context);
        TFHEcipher tfhe(context, public_key);
        vector<vector<uint64_t>> a_vectors = deserialize_long_matrix(env, a_array);
        vector<uint64_t> b_values = jlong_array_to_u64_vector(env, b_array);
        if (a_vectors.size() != b_values.size()) {
            throw invalid_argument("CAPE compressed row-bit a/b size mismatch");
        }
        lock_guard<mutex> lock(g_cape_lwe_to_rgsw_key_mutex);
        auto it = g_cape_lwe_to_rgsw_key_registry.find(static_cast<long>(handle));
        if (it == g_cape_lwe_to_rgsw_key_registry.end()) {
            throw invalid_argument("CAPE LWE-to-RGSW key handle not found");
        }
        const CapeLweToRgswKeyHandle &key_handle = *it->second;
        check_lwe_to_rgsw_key_handle_params(key_handle, parms);
        const vector<RGSWCipher> &key = key_handle.key;
        jobject list = new_array_list(env);
        for (size_t bit_index = 0; bit_index < a_vectors.size(); bit_index++) {
            if (a_vectors[bit_index].size() != key.size()) {
                throw invalid_argument("CAPE compressed row-bit LWE dimension mismatch");
            }
            Plaintext b_plain = rns_bit_plaintext(context, b_values[bit_index]);
            RGSWCipher result;
            tfhe.encrypt(b_plain, result);
            for (size_t i = 0; i < key.size(); i++) {
                uint64_t scalar = a_vectors[bit_index][i];
                if (scalar == 0) {
                    continue;
                }
                RGSWCipher scaled = scalar_multiply_rgsw(key[i], scalar, context);
                sub_rgsw_inplace(result, scaled, evaluator);
            }
            jbyteArray bit_bytes = serialize_rgsw(env, result);
            list_add(env, list, bit_bytes);
            env->DeleteLocalRef(bit_bytes);
        }
        return list;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_convertCompressedRowBitsToRgsw
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray pk_bytes, jobject lwe_to_rgsw_key,
     jobjectArray a_array, jlongArray b_array) {
    try {
        require_non_null(parms_bytes, "encryption parameters");
        require_non_null(pk_bytes, "public key");
        require_non_null(lwe_to_rgsw_key, "serialized CAPE LWE-to-RGSW key");
        require_non_null(a_array, "compressed row-bit a array");
        require_non_null(b_array, "compressed row-bit b array");
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "CAPE", __func__);
        PublicKey public_key = deserialize_public_key(env, pk_bytes, context);
        Evaluator evaluator(context);
        TFHEcipher tfhe(context, public_key);
        vector<vector<uint64_t>> a_vectors = deserialize_long_matrix(env, a_array);
        vector<uint64_t> b_values = jlong_array_to_u64_vector(env, b_array);
        if (a_vectors.size() != b_values.size()) {
            throw invalid_argument("CAPE compressed row-bit a/b size mismatch");
        }
        jint key_size = list_size(env, lwe_to_rgsw_key);
        if (key_size <= 0) {
            throw invalid_argument("empty CAPE LWE-to-RGSW key");
        }
        vector<RGSWCipher> key;
        key.reserve(static_cast<size_t>(key_size));
        for (jint i = 0; i < key_size; i++) {
            auto key_bytes = reinterpret_cast<jbyteArray>(list_get(env, lwe_to_rgsw_key, i));
            key.push_back(deserialize_rgsw(env, key_bytes, context));
            env->DeleteLocalRef(key_bytes);
        }
        jobject list = new_array_list(env);
        for (size_t bit_index = 0; bit_index < a_vectors.size(); bit_index++) {
            if (a_vectors[bit_index].size() != key.size()) {
                throw invalid_argument("CAPE compressed row-bit LWE dimension mismatch");
            }
            Plaintext b_plain = rns_bit_plaintext(context, b_values[bit_index]);
            RGSWCipher result;
            tfhe.encrypt(b_plain, result);
            for (size_t i = 0; i < key.size(); i++) {
                uint64_t scalar = a_vectors[bit_index][i];
                if (scalar == 0) {
                    continue;
                }
                RGSWCipher scaled = scalar_multiply_rgsw(key[i], scalar, context);
                sub_rgsw_inplace(result, scaled, evaluator);
            }
            jbyteArray bit_bytes = serialize_rgsw(env, result);
            list_add(env, list, bit_bytes);
            env->DeleteLocalRef(bit_bytes);
        }
        return list;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generateEncryptedBloomFilter
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray pk_bytes, jbyteArray sk_bytes, jlongArray bloom_bits) {
    try {
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "CAPE", __func__);
        PublicKey public_key = deserialize_public_key(env, pk_bytes, context);
        SecretKey secret_key = deserialize_secret_key(env, sk_bytes, context);
        vector<Plaintext> bloom_plain_chunks = encode_slot_chunks(env, bloom_bits, context);
        Encryptor encryptor(context, public_key);
        encryptor.set_secret_key(secret_key);
        jobject list = new_array_list(env);
        for (Plaintext &bloom_plain : bloom_plain_chunks) {
            Serializable<Ciphertext> bloom_cipher = encryptor.encrypt_symmetric(bloom_plain);
            jbyteArray bloom_bytes = serialize_ciphertext(env, bloom_cipher);
            list_add(env, list, bloom_bytes);
            env->DeleteLocalRef(bloom_bytes);
        }
        return list;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jbyteArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generateEncryptedCoeffBloomFilter
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray pk_bytes, jbyteArray sk_bytes, jlongArray bloom_bits) {
    try {
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "CAPE", __func__);
        PublicKey public_key = deserialize_public_key(env, pk_bytes, context);
        SecretKey secret_key = deserialize_secret_key(env, sk_bytes, context);
        uint64_t plain_modulus = parms.plain_modulus().value();
        size_t coeff_count = parms.poly_modulus_degree();
        jint length = env->GetArrayLength(bloom_bits);
        if (static_cast<size_t>(length) > coeff_count) {
            throw invalid_argument("coefficient Bloom query length must be at most polyModulusDegree");
        }
        jlong *ptr = env->GetLongArrayElements(bloom_bits, JNI_FALSE);
        Plaintext plain(coeff_count);
        plain.set_zero();
        for (jint i = 0; i < length; i++) {
            if (ptr[i] != 0) {
                if (i == 0) {
                    plain[0] = 1;
                } else {
                    // In negacyclic multiplication, x^i * x^(N-i) contributes -1 to coeff[0]. Store -bit so that the
                    // constant term is the positive inner product.
                    plain[coeff_count - static_cast<size_t>(i)] = plain_modulus - 1;
                }
            }
        }
        env->ReleaseLongArrayElements(bloom_bits, ptr, JNI_ABORT);
        Encryptor encryptor(context, public_key);
        encryptor.set_secret_key(secret_key);
        Serializable<Ciphertext> bloom_cipher = encryptor.encrypt_symmetric(plain);
        return serialize_ciphertext(env, bloom_cipher);
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generateEncryptedCoeffBloomScalarBits
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray pk_bytes, jbyteArray sk_bytes, jlongArray bloom_bits) {
    try {
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "CAPE", __func__);
        PublicKey public_key = deserialize_public_key(env, pk_bytes, context);
        SecretKey secret_key = deserialize_secret_key(env, sk_bytes, context);
        size_t coeff_count = parms.poly_modulus_degree();
        jint length = env->GetArrayLength(bloom_bits);
        jlong *ptr = env->GetLongArrayElements(bloom_bits, JNI_FALSE);
        Encryptor encryptor(context, public_key);
        encryptor.set_secret_key(secret_key);
        jobject list = new_array_list(env);
        for (jint i = 0; i < length; i++) {
            Plaintext plain(coeff_count);
            plain.set_zero();
            plain[0] = ptr[i] == 0 ? 0 : 1;
            Serializable<Ciphertext> bit_cipher = encryptor.encrypt_symmetric(plain);
            jbyteArray bit_bytes = serialize_ciphertext(env, bit_cipher);
            list_add(env, list, bit_bytes);
            env->DeleteLocalRef(bit_bytes);
        }
        env->ReleaseLongArrayElements(bloom_bits, ptr, JNI_ABORT);
        return list;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_encryptBloomFilter
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray pk_bytes, jlongArray bloom_bits) {
    try {
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "CAPE", __func__);
        PublicKey public_key = deserialize_public_key(env, pk_bytes, context);
        vector<Plaintext> bloom_plain_chunks = encode_slot_chunks(env, bloom_bits, context);
        Encryptor encryptor(context, public_key);
        jobject list = new_array_list(env);
        for (Plaintext &bloom_plain : bloom_plain_chunks) {
            Serializable<Ciphertext> bloom_cipher = encryptor.encrypt(bloom_plain);
            jbyteArray bloom_bytes = serialize_ciphertext(env, bloom_cipher);
            list_add(env, list, bloom_bytes);
            env->DeleteLocalRef(bloom_bytes);
        }
        return list;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_preprocessDatabase
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jobjectArray fusepir_matrices, jobjectArray value_bloom_filters) {
    try {
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "CAPE", __func__);
        vector<Plaintext> plaintexts;
        if (env->GetArrayLength(fusepir_matrices) > 0) {
            auto matrix_data = deserialize_matrices(env, fusepir_matrices);
            uint32_t coeff_count = parms.poly_modulus_degree();
            if (matrix_data.empty() || matrix_data[0].empty()) {
                throw invalid_argument("invalid CAPE matrix shape");
            }
            size_t row_size = matrix_data[0][0].size();
            int col_num = 0;
            int blocks_per_packed_matrix = 0;
            // CAPE Java stores row size = matrixColNum * blocksPerPackedMatrix. Infer the same shape by using the
            // maximum block offset that preserves the FUSE_PIR row polynomial layout. Stage 8 tests use this encoded state
            // only through generateFusePirCandidateReply, which receives explicit colNum and blocksPerPackedMatrix.
            plaintexts.reserve(matrix_data.size() * matrix_data[0].size());
            for (const auto &group : matrix_data) {
                for (const auto &row : group) {
                    Plaintext plain(coeff_count);
                    plain.set_zero();
                    for (size_t i = 0; i < row.size(); i++) {
                        uint64_t raw = row[i];
                        if (raw == 0) {
                            continue;
                        }
                        plain[i] = raw % parms.plain_modulus().value();
                    }
                    plaintexts.push_back(plain);
                }
            }
        }
        if (env->GetArrayLength(value_bloom_filters) > 0) {
            vector<Plaintext> bloom_plaintexts = encode_slot_plaintexts(env, value_bloom_filters, context);
            plaintexts.insert(plaintexts.end(), bloom_plaintexts.begin(), bloom_plaintexts.end());
        }
        return serialize_plaintexts(env, plaintexts);
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generateFusePirCandidateReply
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray pk_bytes, jobject column_queries,
     jobject encrypted_row_bits, jobject encoded_matrices, jint payload_block_num, jint row_num, jint col_num,
     jint blocks_per_packed_matrix) {
    try {
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "CAPE", __func__);
        Evaluator evaluator(context);
        PublicKey public_key = deserialize_public_key(env, pk_bytes, context);
        vector<Ciphertext> queries = deserialize_ciphertexts(env, column_queries, context);
        vector<Plaintext> raw_matrix_rows = deserialize_plaintexts(env, encoded_matrices, context);
        uint32_t coeff_count = parms.poly_modulus_degree();
        if (queries.size() != 3) {
            throw invalid_argument("CAPE candidate retrieval needs exactly three BFF position queries");
        }
        if (blocks_per_packed_matrix <= 0) {
            throw invalid_argument("blocksPerPackedMatrix must be positive");
        }
        jint packed_matrix_group_num = (payload_block_num + blocks_per_packed_matrix - 1)
            / blocks_per_packed_matrix;
        jint row_stride = col_num * blocks_per_packed_matrix;
        if (static_cast<uint64_t>(row_num) * static_cast<uint64_t>(row_stride) > coeff_count) {
            throw invalid_argument("CAPE packed matrix requires rowNum * rowStride <= polyModulusDegree");
        }
        jint row_bit_num = static_cast<jint>(ceil_log2(static_cast<uint32_t>(row_num)));
        if (list_size(env, encrypted_row_bits) != static_cast<jint>(3 * row_bit_num)) {
            throw invalid_argument("CAPE flattened encrypted row bits size mismatch");
        }
        if (raw_matrix_rows.size() != static_cast<size_t>(packed_matrix_group_num * row_num)) {
            throw invalid_argument(
                "encoded matrix size mismatch: actual=" + to_string(raw_matrix_rows.size())
                    + ", expected=" + to_string(static_cast<size_t>(packed_matrix_group_num * row_num))
                    + ", payloadBlockNum=" + to_string(payload_block_num)
                    + ", blocksPerPackedMatrix=" + to_string(blocks_per_packed_matrix)
                    + ", rowNum=" + to_string(row_num)
            );
        }
        vector<vector<RGSWCipher>> row_bits(3);
        for (jint a = 0; a < 3; a++) {
            row_bits[a].reserve(row_bit_num);
            for (jint b = 0; b < row_bit_num; b++) {
                auto bit_bytes = reinterpret_cast<jbyteArray>(list_get(env, encrypted_row_bits, a * row_bit_num + b));
                row_bits[a].push_back(deserialize_rgsw(env, bit_bytes, context));
                env->DeleteLocalRef(bit_bytes);
            }
        }
        TFHEcipher tfhe(context, public_key);
        Encryptor encryptor(context, public_key);
        if (payload_block_num > static_cast<jint>(coeff_count)) {
            throw invalid_argument("payloadBlockNum exceeds packing capacity");
        }
        Ciphertext packed_reply;
        bool packed_reply_initialized = false;
        for (jint group = 0; group < packed_matrix_group_num; group++) {
            Ciphertext group_reply;
            bool initialized = false;
            for (jint a = 0; a < 3; a++) {
                Ciphertext packed_col;
                bool packed_initialized = false;
                for (jint row = 0; row < row_num; row++) {
                    const Plaintext &raw_row = raw_matrix_rows[group * row_num + row];
                    if (raw_row.is_zero()) {
                        continue;
                    }
                    Plaintext matrix_row = build_shifted_matrix_row(
                        raw_row, parms, col_num, blocks_per_packed_matrix
                    );
                    if (matrix_row.is_zero()) {
                        continue;
                    }
                    Ciphertext selected;
                    evaluator.multiply_plain(queries[a], matrix_row, selected);
                    if (selected.is_transparent()) {
                        continue;
                    }
                    Ciphertext coeff_selected = selected;
                    if (row > 0) {
                        coeff_selected = mul_by_monomial(coeff_selected, row * row_stride, context);
                    }
                    if (!packed_initialized) {
                        packed_col = coeff_selected;
                        packed_initialized = true;
                    } else if (!coeff_selected.is_transparent()) {
                        evaluator.add_inplace(packed_col, coeff_selected);
                    }
                }
                if (!packed_initialized) {
                    continue;
                }
                Ciphertext rotated = blind_rotate_to_zero(
                    packed_col, row_bits[a], row_num, row_stride, context, tfhe, evaluator
                );
                if (!initialized) {
                    group_reply = rotated;
                    initialized = true;
                } else if (!rotated.is_transparent()) {
                    evaluator.add_inplace(group_reply, rotated);
                }
            }
            if (!initialized) {
                encryptor.encrypt_zero(group_reply);
            }
            if (group_reply.is_ntt_form()) {
                evaluator.transform_from_ntt_inplace(group_reply);
            }
            int global_offset = group * blocks_per_packed_matrix;
            Ciphertext shifted_reply = global_offset == 0
                ? group_reply
                : mul_by_monomial(group_reply, global_offset, context);
            if (!packed_reply_initialized) {
                packed_reply = shifted_reply;
                packed_reply_initialized = true;
            } else if (!shifted_reply.is_transparent()) {
                evaluator.add_inplace(packed_reply, shifted_reply);
            }
        }
        if (!packed_reply_initialized) {
            encryptor.encrypt_zero(packed_reply);
        }
        vector<Ciphertext> replies;
        replies.push_back(packed_reply);
        return serialize_ciphertexts(env, replies);
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_mergePackedValueAndScoreReplies
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jobject encrypted_value_payloads, jobject encrypted_scores,
     jint value_payload_coeff_num, jint score_coeff_num) {
    try {
        if (value_payload_coeff_num <= 0 || score_coeff_num <= 0) {
            throw invalid_argument("CAPE packed result value/score coeff counts must be positive");
        }
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "CAPE", __func__);
        Evaluator evaluator(context);
        vector<Ciphertext> value_payloads = deserialize_ciphertexts(env, encrypted_value_payloads, context);
        vector<Ciphertext> scores = deserialize_ciphertexts(env, encrypted_scores, context);
        uint32_t coeff_count = parms.poly_modulus_degree();
        uint64_t total_coeff_num = static_cast<uint64_t>(value_payload_coeff_num)
            + static_cast<uint64_t>(score_coeff_num);
        size_t result_count = static_cast<size_t>((total_coeff_num + coeff_count - 1) / coeff_count);
        vector<Ciphertext> results(result_count);
        vector<bool> initialized(result_count, false);

        for (size_t value_index = 0; value_index < value_payloads.size(); value_index++) {
            uint64_t global_offset = static_cast<uint64_t>(value_index) * coeff_count;
            if (global_offset >= static_cast<uint64_t>(value_payload_coeff_num)) {
                break;
            }
            size_t result_index = static_cast<size_t>(global_offset / coeff_count);
            int local_offset = static_cast<int>(global_offset % coeff_count);
            Ciphertext shifted = local_offset == 0
                ? value_payloads[value_index]
                : mul_by_monomial(value_payloads[value_index], local_offset, context);
            if (!initialized[result_index]) {
                results[result_index] = shifted;
                initialized[result_index] = true;
            } else if (!shifted.is_transparent()) {
                evaluator.add_inplace(results[result_index], shifted);
            }
        }

        uint64_t score_offset = static_cast<uint64_t>(value_payload_coeff_num);
        for (size_t score_ct_index = 0; score_ct_index < scores.size(); score_ct_index++) {
            uint64_t score_source_start = static_cast<uint64_t>(score_ct_index) * coeff_count;
            if (score_source_start >= static_cast<uint64_t>(score_coeff_num)) {
                break;
            }
            uint64_t remaining = min<uint64_t>(
                coeff_count, static_cast<uint64_t>(score_coeff_num) - score_source_start
            );
            uint64_t source_offset = 0;
            while (remaining > 0) {
                uint64_t score_global_start = score_offset + score_source_start + source_offset;
                size_t result_index = static_cast<size_t>(score_global_start / coeff_count);
                int result_local_offset = static_cast<int>(score_global_start % coeff_count);
                uint64_t piece_len = min<uint64_t>(remaining, coeff_count - result_local_offset);
                Ciphertext piece;
                if (source_offset == 0 && piece_len == remaining) {
                    piece = scores[score_ct_index];
                } else {
                    throw invalid_argument("CAPE packed result score split across ciphertexts is not implemented");
                }
                int shift = result_local_offset - static_cast<int>(source_offset);
                Ciphertext shifted = shift == 0 ? piece : mul_by_monomial(piece, shift, context);
                if (!initialized[result_index]) {
                    results[result_index] = shifted;
                    initialized[result_index] = true;
                } else if (!shifted.is_transparent()) {
                    evaluator.add_inplace(results[result_index], shifted);
                }
                remaining -= piece_len;
                source_offset += piece_len;
            }
        }

        for (size_t result_index = 0; result_index < results.size(); result_index++) {
            if (!initialized[result_index]) {
                throw invalid_argument("CAPE packed result assembly produced an empty ciphertext slot");
            }
            if (results[result_index].is_ntt_form()) {
                evaluator.transform_from_ntt_inplace(results[result_index]);
            }
        }
        return serialize_ciphertexts(env, results);
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generateBloomInnerProductsForTest
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray, jbyteArray galois_keys_bytes,
     jobject encrypted_bloom_filter, jobject encoded_value_bloom_filters) {
        GaloisKeys *galois_keys = nullptr;
    try {
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "CAPE", __func__);
        Evaluator evaluator(context);
        galois_keys = deserialize_galois_keys(env, galois_keys_bytes, context);
        vector<Ciphertext> bloom_queries = deserialize_ciphertexts(env, encrypted_bloom_filter, context);
        if (bloom_queries.empty()) {
            throw invalid_argument("packed encrypted Bloom Filter must contain at least one ciphertext");
        }
        vector<Plaintext> value_bloom_filters = deserialize_plaintexts(env, encoded_value_bloom_filters, context);
        if (value_bloom_filters.size() % bloom_queries.size() != 0) {
            throw invalid_argument("encoded value Bloom Filter chunk size mismatch");
        }
        size_t chunk_num = bloom_queries.size();
        size_t value_num = value_bloom_filters.size() / chunk_num;
        BatchEncoder encoder(context);
        vector<Ciphertext> scores;
        scores.reserve(value_num);
        for (size_t value_index = 0; value_index < value_num; value_index++) {
            Ciphertext score;
            bool initialized = false;
            for (size_t chunk = 0; chunk < chunk_num; chunk++) {
                Ciphertext chunk_score;
                evaluator.multiply_plain(
                    bloom_queries[chunk], value_bloom_filters[value_index * chunk_num + chunk], chunk_score
                );
                add_all_slots_inplace(evaluator, chunk_score, *galois_keys, encoder.slot_count());
                if (!initialized) {
                    score = chunk_score;
                    initialized = true;
                } else if (!chunk_score.is_transparent()) {
                    evaluator.add_inplace(score, chunk_score);
                }
            }
            scores.push_back(score);
        }
        delete galois_keys;
        return serialize_ciphertexts(env, scores);
    } catch (const exception &e) {
        if (galois_keys != nullptr) {
            delete galois_keys;
        }
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generatePackedBloomInnerProductsForTest
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray, jbyteArray galois_keys_bytes,
     jobject encrypted_bloom_filter, jobject encoded_value_bloom_filters) {
    GaloisKeys *galois_keys = nullptr;
    try {
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "CAPE", __func__);
        Evaluator evaluator(context);
        galois_keys = deserialize_galois_keys(env, galois_keys_bytes, context);
        vector<Ciphertext> bloom_queries = deserialize_ciphertexts(env, encrypted_bloom_filter, context);
        if (bloom_queries.empty()) {
            throw invalid_argument("packed encrypted Bloom Filter must contain at least one ciphertext");
        }
        vector<Plaintext> value_bloom_filters = deserialize_plaintexts(env, encoded_value_bloom_filters, context);
        if (value_bloom_filters.size() % bloom_queries.size() != 0) {
            throw invalid_argument("encoded value Bloom Filter chunk size mismatch");
        }
        BatchEncoder encoder(context);
        size_t slot_count = encoder.slot_count();
        size_t chunk_num = bloom_queries.size();
        size_t value_num = value_bloom_filters.size() / chunk_num;
        if (value_num > slot_count) {
            throw invalid_argument("score packing for more than slot_count values is not implemented yet");
        }
        vector<Ciphertext> packed_scores;
        if (value_num == 0) {
            delete galois_keys;
            return serialize_ciphertexts(env, packed_scores);
        }
        Ciphertext packed_score;
        bool initialized = false;
        for (size_t value_index = 0; value_index < value_num; value_index++) {
            Ciphertext score;
            bool score_initialized = false;
            for (size_t chunk = 0; chunk < chunk_num; chunk++) {
                Ciphertext chunk_score;
                evaluator.multiply_plain(
                    bloom_queries[chunk], value_bloom_filters[value_index * chunk_num + chunk], chunk_score
                );
                add_all_slots_inplace(evaluator, chunk_score, *galois_keys, slot_count);
                if (!score_initialized) {
                    score = chunk_score;
                    score_initialized = true;
                } else if (!chunk_score.is_transparent()) {
                    evaluator.add_inplace(score, chunk_score);
                }
            }
            vector<uint64_t> mask(slot_count, 0ULL);
            mask[value_index] = 1ULL;
            Plaintext mask_plain;
            encoder.encode(mask, mask_plain);
            evaluator.multiply_plain_inplace(score, mask_plain);
            if (!initialized) {
                packed_score = score;
                initialized = true;
            } else if (!score.is_transparent()) {
                evaluator.add_inplace(packed_score, score);
            }
        }
        packed_scores.push_back(packed_score);
        delete galois_keys;
        return serialize_ciphertexts(env, packed_scores);
    } catch (const exception &e) {
        if (galois_keys != nullptr) {
            delete galois_keys;
        }
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generateCtCtBloomInnerProducts
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray, jbyteArray relin_keys_bytes,
     jbyteArray galois_keys_bytes, jobject encrypted_query_bloom_filter, jobject encrypted_candidate_bloom_filters) {
    GaloisKeys *galois_keys = nullptr;
    try {
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "CAPE", __func__);
        Evaluator evaluator(context);
        RelinKeys relin_keys = deserialize_relin_keys(env, relin_keys_bytes, context);
        galois_keys = deserialize_galois_keys(env, galois_keys_bytes, context);
        vector<Ciphertext> query_blooms = deserialize_ciphertexts(env, encrypted_query_bloom_filter, context);
        vector<Ciphertext> candidate_blooms = deserialize_ciphertexts(env, encrypted_candidate_bloom_filters, context);
        if (query_blooms.empty()) {
            throw invalid_argument("encrypted query Bloom Filter must contain at least one ciphertext");
        }
        if (candidate_blooms.size() % query_blooms.size() != 0) {
            throw invalid_argument("encrypted candidate Bloom Filter chunk size mismatch");
        }
        BatchEncoder encoder(context);
        size_t slot_count = encoder.slot_count();
        size_t chunk_num = query_blooms.size();
        size_t value_num = candidate_blooms.size() / chunk_num;
        if (value_num > slot_count) {
            throw invalid_argument("score packing for more than slot_count values is not implemented yet");
        }
        vector<Ciphertext> packed_scores;
        if (value_num == 0) {
            delete galois_keys;
            return serialize_ciphertexts(env, packed_scores);
        }
        Ciphertext packed_score;
        bool initialized = false;
        for (size_t value_index = 0; value_index < value_num; value_index++) {
            Ciphertext score;
            bool score_initialized = false;
            for (size_t chunk = 0; chunk < chunk_num; chunk++) {
                Ciphertext chunk_score;
                evaluator.multiply(
                    candidate_blooms[value_index * chunk_num + chunk], query_blooms[chunk], chunk_score
                );
                evaluator.relinearize_inplace(chunk_score, relin_keys);
                add_all_slots_inplace(evaluator, chunk_score, *galois_keys, slot_count);
                if (!score_initialized) {
                    score = chunk_score;
                    score_initialized = true;
                } else if (!chunk_score.is_transparent()) {
                    evaluator.add_inplace(score, chunk_score);
                }
            }
            vector<uint64_t> mask(slot_count, 0ULL);
            mask[value_index] = 1ULL;
            Plaintext mask_plain;
            encoder.encode(mask, mask_plain);
            evaluator.multiply_plain_inplace(score, mask_plain);
            if (!initialized) {
                packed_score = score;
                initialized = true;
            } else if (!score.is_transparent()) {
                evaluator.add_inplace(packed_score, score);
            }
        }
        packed_scores.push_back(packed_score);
        delete galois_keys;
        return serialize_ciphertexts(env, packed_scores);
    } catch (const exception &e) {
        if (galois_keys != nullptr) {
            delete galois_keys;
        }
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generateCoeffCtCtBloomInnerProducts
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray, jbyteArray relin_keys_bytes,
     jbyteArray encrypted_coeff_query_bloom_filter, jbyteArray encrypted_candidate_bloom_payload,
     jint max_value_num_per_keyword, jint bloom_bit_length) {
    try {
        if (max_value_num_per_keyword <= 0 || bloom_bit_length <= 0) {
            throw invalid_argument("invalid CAPE coefficient Bloom score parameters");
        }
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "CAPE", __func__);
        Evaluator evaluator(context);
        RelinKeys relin_keys = deserialize_relin_keys(env, relin_keys_bytes, context);
        Ciphertext query_bloom = deserialize_ciphertext(env, encrypted_coeff_query_bloom_filter, context);
        Ciphertext candidate_bloom = deserialize_ciphertext(env, encrypted_candidate_bloom_payload, context);
        size_t coeff_count = parms.poly_modulus_degree();
        if (static_cast<uint64_t>(max_value_num_per_keyword) * static_cast<uint64_t>(bloom_bit_length) >= coeff_count) {
            throw invalid_argument("candidate Bloom payload exceeds coefficient score capacity");
        }
        jobject scores = new_array_list(env);
        for (jint value_index = 0; value_index < max_value_num_per_keyword; value_index++) {
            int offset = value_index * bloom_bit_length;
            Ciphertext shifted_query = offset == 0 ? query_bloom : mul_by_monomial(query_bloom, -offset, context);
            Ciphertext score;
            evaluator.multiply(candidate_bloom, shifted_query, score);
            evaluator.relinearize_inplace(score, relin_keys);
            jbyteArray score_bytes = serialize_ciphertext(env, score);
            list_add(env, scores, score_bytes);
            env->DeleteLocalRef(score_bytes);
        }
        return scores;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generateCoeffCtCtBloomInnerProductsFromGroups
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray, jbyteArray relin_keys_bytes,
     jbyteArray encrypted_coeff_query_bloom_filter, jobject encrypted_candidate_bloom_groups,
     jint max_value_num_per_keyword, jint bloom_bit_length, jint blocks_per_packed_matrix) {
    try {
        if (max_value_num_per_keyword <= 0 || bloom_bit_length <= 0 || blocks_per_packed_matrix <= 0) {
            throw invalid_argument("invalid CAPE grouped coefficient Bloom score parameters");
        }
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "CAPE", __func__);
        Evaluator evaluator(context);
        RelinKeys relin_keys = deserialize_relin_keys(env, relin_keys_bytes, context);
        Ciphertext query_bloom = deserialize_ciphertext(env, encrypted_coeff_query_bloom_filter, context);
        vector<Ciphertext> candidate_groups = deserialize_ciphertexts(env, encrypted_candidate_bloom_groups, context);
        if (candidate_groups.empty()) {
            throw invalid_argument("encrypted candidate Bloom groups must not be empty");
        }
        size_t coeff_count = parms.poly_modulus_degree();
        if (static_cast<size_t>(blocks_per_packed_matrix) >= coeff_count) {
            throw invalid_argument("blocksPerPackedMatrix exceeds coefficient capacity");
        }
        jobject scores = new_array_list(env);
        for (jint value_index = 0; value_index < max_value_num_per_keyword; value_index++) {
            Ciphertext total_score;
            bool initialized = false;
            for (size_t group = 0; group < candidate_groups.size(); group++) {
                int shift = static_cast<int>(group) * blocks_per_packed_matrix - value_index * bloom_bit_length;
                Ciphertext shifted_query = shift == 0 ? query_bloom : mul_by_monomial(query_bloom, shift, context);
                Ciphertext product;
                evaluator.multiply(candidate_groups[group], shifted_query, product);
                evaluator.relinearize_inplace(product, relin_keys);
                if (!initialized) {
                    total_score = product;
                    initialized = true;
                } else if (!product.is_transparent()) {
                    evaluator.add_inplace(total_score, product);
                }
            }
            jbyteArray score_bytes = serialize_ciphertext(env, total_score);
            list_add(env, scores, score_bytes);
            env->DeleteLocalRef(score_bytes);
        }
        return scores;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generateCoeffCtCtBloomInnerProductsFromGroupQueries
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray, jbyteArray relin_keys_bytes,
     jobject encrypted_coeff_query_bloom_groups, jobject encrypted_candidate_bloom_groups,
     jint max_value_num_per_keyword) {
    try {
        if (max_value_num_per_keyword <= 0) {
            throw invalid_argument("invalid CAPE grouped query Bloom score parameters");
        }
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "CAPE", __func__);
        Evaluator evaluator(context);
        RelinKeys relin_keys = deserialize_relin_keys(env, relin_keys_bytes, context);
        vector<Ciphertext> query_groups = deserialize_ciphertexts(env, encrypted_coeff_query_bloom_groups, context);
        vector<Ciphertext> candidate_groups = deserialize_ciphertexts(env, encrypted_candidate_bloom_groups, context);
        if (candidate_groups.empty()) {
            throw invalid_argument("encrypted candidate Bloom groups must not be empty");
        }
        if (query_groups.size() != static_cast<size_t>(max_value_num_per_keyword) * candidate_groups.size()) {
            throw invalid_argument("encrypted query Bloom group size mismatch");
        }
        jobject scores = new_array_list(env);
        for (jint value_index = 0; value_index < max_value_num_per_keyword; value_index++) {
            Ciphertext total_score;
            bool initialized = false;
            for (size_t group = 0; group < candidate_groups.size(); group++) {
                Ciphertext product;
                evaluator.multiply(
                    candidate_groups[group],
                    query_groups[static_cast<size_t>(value_index) * candidate_groups.size() + group],
                    product
                );
                evaluator.relinearize_inplace(product, relin_keys);
                if (!initialized) {
                    total_score = product;
                    initialized = true;
                } else if (!product.is_transparent()) {
                    evaluator.add_inplace(total_score, product);
                }
            }
            jbyteArray score_bytes = serialize_ciphertext(env, total_score);
            list_add(env, scores, score_bytes);
            env->DeleteLocalRef(score_bytes);
        }
        return scores;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generatePackedCoeffCtCtBloomInnerProductsFromGroupQueries
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray, jbyteArray relin_keys_bytes,
     jbyteArray galois_keys_bytes, jobject encrypted_coeff_query_bloom_groups,
     jobject encrypted_candidate_bloom_groups, jint max_value_num_per_keyword) {
    GaloisKeys *galois_keys = nullptr;
    try {
        if (max_value_num_per_keyword <= 0) {
            throw invalid_argument("invalid CAPE packed grouped query Bloom score parameters");
        }
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "CAPE", __func__);
        Evaluator evaluator(context);
        RelinKeys relin_keys = deserialize_relin_keys(env, relin_keys_bytes, context);
        galois_keys = deserialize_galois_keys(env, galois_keys_bytes, context);
        vector<Ciphertext> query_groups = deserialize_ciphertexts(env, encrypted_coeff_query_bloom_groups, context);
        vector<Ciphertext> candidate_groups = deserialize_ciphertexts(env, encrypted_candidate_bloom_groups, context);
        if (candidate_groups.empty()) {
            throw invalid_argument("encrypted candidate Bloom groups must not be empty");
        }
        if (query_groups.size() != static_cast<size_t>(max_value_num_per_keyword) * candidate_groups.size()) {
            throw invalid_argument("encrypted query Bloom group size mismatch");
        }
        if (static_cast<size_t>(max_value_num_per_keyword) > parms.poly_modulus_degree()) {
            throw invalid_argument("maxValueNumPerKeyword exceeds score packing capacity");
        }
        Ciphertext packed_score;
        bool packed_initialized = false;
        for (jint value_index = 0; value_index < max_value_num_per_keyword; value_index++) {
            Ciphertext total_score;
            bool initialized = false;
            for (size_t group = 0; group < candidate_groups.size(); group++) {
                Ciphertext product;
                evaluator.multiply(
                    candidate_groups[group],
                    query_groups[static_cast<size_t>(value_index) * candidate_groups.size() + group],
                    product
                );
                evaluator.relinearize_inplace(product, relin_keys);
                if (!initialized) {
                    total_score = product;
                    initialized = true;
                } else if (!product.is_transparent()) {
                    evaluator.add_inplace(total_score, product);
                }
            }
            keep_constant_coefficient_inplace(evaluator, total_score, *galois_keys, context);
            Ciphertext shifted_score = value_index == 0
                ? total_score
                : mul_by_monomial(total_score, value_index, context);
            if (!packed_initialized) {
                packed_score = shifted_score;
                packed_initialized = true;
            } else if (!shifted_score.is_transparent()) {
                evaluator.add_inplace(packed_score, shifted_score);
            }
        }
        jobject scores = new_array_list(env);
        jbyteArray score_bytes = serialize_ciphertext(env, packed_score);
        list_add(env, scores, score_bytes);
        env->DeleteLocalRef(score_bytes);
        delete galois_keys;
        return scores;
    } catch (const exception &e) {
        if (galois_keys != nullptr) {
            delete galois_keys;
        }
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generateFusedPackedCoeffCtCtBloomScores
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray pk_bytes, jbyteArray relin_keys_bytes,
     jbyteArray galois_keys_bytes, jobject column_queries, jobject encrypted_row_bits, jobject encoded_matrices,
     jobject encrypted_coeff_query_bloom_groups, jint payload_block_num, jint row_num, jint col_num,
     jint blocks_per_packed_matrix, jint max_value_num_per_keyword) {
    GaloisKeys *galois_keys = nullptr;
    try {
        if (max_value_num_per_keyword <= 0 || payload_block_num <= 0 || row_num <= 0 || col_num <= 0
            || blocks_per_packed_matrix <= 0) {
            throw invalid_argument("invalid CAPE fused packed score parameters");
        }
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "CAPE", __func__);
        Evaluator evaluator(context);
        PublicKey public_key = deserialize_public_key(env, pk_bytes, context);
        RelinKeys relin_keys = deserialize_relin_keys(env, relin_keys_bytes, context);
        galois_keys = deserialize_galois_keys(env, galois_keys_bytes, context);
        vector<Ciphertext> queries = deserialize_ciphertexts(env, column_queries, context);
        vector<Plaintext> raw_matrix_rows = deserialize_plaintexts(env, encoded_matrices, context);
        vector<Ciphertext> query_groups = deserialize_ciphertexts(env, encrypted_coeff_query_bloom_groups, context);
        uint32_t coeff_count = parms.poly_modulus_degree();
        if (queries.size() != 3) {
            throw invalid_argument("CAPE fused score needs exactly three BFF position queries");
        }
        if (static_cast<size_t>(max_value_num_per_keyword) > coeff_count) {
            throw invalid_argument("maxValueNumPerKeyword exceeds score packing capacity");
        }
        jint packed_matrix_group_num = (payload_block_num + blocks_per_packed_matrix - 1)
            / blocks_per_packed_matrix;
        if (query_groups.size() != static_cast<size_t>(max_value_num_per_keyword) * packed_matrix_group_num) {
            throw invalid_argument("encrypted query Bloom group size mismatch in fused score");
        }
        jint row_stride = col_num * blocks_per_packed_matrix;
        if (static_cast<uint64_t>(row_num) * static_cast<uint64_t>(row_stride) > coeff_count) {
            throw invalid_argument("CAPE packed matrix requires rowNum * rowStride <= polyModulusDegree");
        }
        jint row_bit_num = static_cast<jint>(ceil_log2(static_cast<uint32_t>(row_num)));
        if (list_size(env, encrypted_row_bits) != static_cast<jint>(3 * row_bit_num)) {
            throw invalid_argument("CAPE flattened encrypted row bits size mismatch");
        }
        if (raw_matrix_rows.size() != static_cast<size_t>(packed_matrix_group_num * row_num)) {
            throw invalid_argument("encoded matrix size mismatch in fused score");
        }
        vector<vector<RGSWCipher>> row_bits(3);
        for (jint a = 0; a < 3; a++) {
            row_bits[a].reserve(row_bit_num);
            for (jint b = 0; b < row_bit_num; b++) {
                auto bit_bytes = reinterpret_cast<jbyteArray>(list_get(env, encrypted_row_bits, a * row_bit_num + b));
                row_bits[a].push_back(deserialize_rgsw(env, bit_bytes, context));
                env->DeleteLocalRef(bit_bytes);
            }
        }
        TFHEcipher tfhe(context, public_key);
        Encryptor encryptor(context, public_key);
        vector<Ciphertext> total_scores(static_cast<size_t>(max_value_num_per_keyword));
        vector<bool> total_score_initialized(static_cast<size_t>(max_value_num_per_keyword), false);
        for (jint group = 0; group < packed_matrix_group_num; group++) {
            Ciphertext group_reply;
            bool initialized = false;
            for (jint a = 0; a < 3; a++) {
                Ciphertext packed_col;
                bool packed_initialized = false;
                for (jint row = 0; row < row_num; row++) {
                    const Plaintext &raw_row = raw_matrix_rows[group * row_num + row];
                    if (raw_row.is_zero()) {
                        continue;
                    }
                    Plaintext matrix_row = build_shifted_matrix_row(
                        raw_row, parms, col_num, blocks_per_packed_matrix
                    );
                    if (matrix_row.is_zero()) {
                        continue;
                    }
                    Ciphertext selected;
                    evaluator.multiply_plain(queries[a], matrix_row, selected);
                    if (selected.is_transparent()) {
                        continue;
                    }
                    Ciphertext coeff_selected = selected;
                    if (row > 0) {
                        coeff_selected = mul_by_monomial(coeff_selected, row * row_stride, context);
                    }
                    if (!packed_initialized) {
                        packed_col = coeff_selected;
                        packed_initialized = true;
                    } else if (!coeff_selected.is_transparent()) {
                        evaluator.add_inplace(packed_col, coeff_selected);
                    }
                }
                if (!packed_initialized) {
                    continue;
                }
                Ciphertext rotated = blind_rotate_to_zero(
                    packed_col, row_bits[a], row_num, row_stride, context, tfhe, evaluator
                );
                if (!initialized) {
                    group_reply = rotated;
                    initialized = true;
                } else if (!rotated.is_transparent()) {
                    evaluator.add_inplace(group_reply, rotated);
                }
            }
            if (!initialized) {
                encryptor.encrypt_zero(group_reply);
            }
            if (group_reply.is_ntt_form()) {
                evaluator.transform_from_ntt_inplace(group_reply);
            }
            for (jint value_index = 0; value_index < max_value_num_per_keyword; value_index++) {
                Ciphertext product;
                evaluator.multiply(
                    group_reply,
                    query_groups[static_cast<size_t>(value_index) * packed_matrix_group_num + group],
                    product
                );
                evaluator.relinearize_inplace(product, relin_keys);
                if (!total_score_initialized[value_index]) {
                    total_scores[value_index] = product;
                    total_score_initialized[value_index] = true;
                } else if (!product.is_transparent()) {
                    evaluator.add_inplace(total_scores[value_index], product);
                }
            }
        }
        Ciphertext packed_score;
        bool packed_initialized = false;
        for (jint value_index = 0; value_index < max_value_num_per_keyword; value_index++) {
            if (!total_score_initialized[value_index]) {
                encryptor.encrypt_zero(total_scores[value_index]);
            }
            keep_constant_coefficient_inplace(evaluator, total_scores[value_index], *galois_keys, context);
            Ciphertext shifted_score = value_index == 0
                ? total_scores[value_index]
                : mul_by_monomial(total_scores[value_index], value_index, context);
            if (!packed_initialized) {
                packed_score = shifted_score;
                packed_initialized = true;
            } else if (!shifted_score.is_transparent()) {
                evaluator.add_inplace(packed_score, shifted_score);
            }
        }
        jobject scores = new_array_list(env);
        jbyteArray score_bytes = serialize_ciphertext(env, packed_score);
        list_add(env, scores, score_bytes);
        env->DeleteLocalRef(score_bytes);
        delete galois_keys;
        return scores;
    } catch (const exception &e) {
        if (galois_keys != nullptr) {
            delete galois_keys;
        }
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generateFusedPackedCoeffCtCtBloomScoresGlobalTiled
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray pk_bytes, jbyteArray relin_keys_bytes,
     jbyteArray galois_keys_bytes, jobject column_queries, jobject encrypted_row_bits, jobject encoded_matrices,
     jobject encrypted_coeff_query_bloom_groups, jint payload_block_num, jint row_num, jint col_num,
     jint blocks_per_packed_matrix, jint max_value_num_per_keyword, jint bloom_bit_length) {
    GaloisKeys *galois_keys = nullptr;
    try {
        if (max_value_num_per_keyword <= 0 || payload_block_num <= 0 || row_num <= 0 || col_num <= 0
            || blocks_per_packed_matrix <= 0 || bloom_bit_length <= 0) {
            throw invalid_argument("invalid CAPE global tiled fused packed score parameters");
        }
        if (payload_block_num != max_value_num_per_keyword * bloom_bit_length) {
            throw invalid_argument("CAPE global tiled payload block count mismatch");
        }
        if (bloom_bit_length % blocks_per_packed_matrix != 0) {
            throw invalid_argument("CAPE global tiled schedule requires blocksPerPackedMatrix to divide bloomBitLength");
        }
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "CAPE", __func__);
        Evaluator evaluator(context);
        PublicKey public_key = deserialize_public_key(env, pk_bytes, context);
        RelinKeys relin_keys = deserialize_relin_keys(env, relin_keys_bytes, context);
        galois_keys = deserialize_galois_keys(env, galois_keys_bytes, context);
        vector<Ciphertext> queries = deserialize_ciphertexts(env, column_queries, context);
        vector<Plaintext> raw_matrix_rows = deserialize_plaintexts(env, encoded_matrices, context);
        vector<Ciphertext> query_groups = deserialize_ciphertexts(env, encrypted_coeff_query_bloom_groups, context);
        uint32_t coeff_count = parms.poly_modulus_degree();
        if (queries.size() != 3) {
            throw invalid_argument("CAPE global tiled fused score needs exactly three BFF position queries");
        }
        if (static_cast<size_t>(max_value_num_per_keyword) > coeff_count) {
            throw invalid_argument("maxValueNumPerKeyword exceeds score packing capacity");
        }
        jint packed_matrix_group_num = (payload_block_num + blocks_per_packed_matrix - 1)
            / blocks_per_packed_matrix;
        if (query_groups.size() != static_cast<size_t>(packed_matrix_group_num)) {
            throw invalid_argument("encrypted global tiled query Bloom group size mismatch in fused score");
        }
        jint row_stride = col_num * blocks_per_packed_matrix;
        if (static_cast<uint64_t>(row_num) * static_cast<uint64_t>(row_stride) > coeff_count) {
            throw invalid_argument("CAPE packed matrix requires rowNum * rowStride <= polyModulusDegree");
        }
        jint row_bit_num = static_cast<jint>(ceil_log2(static_cast<uint32_t>(row_num)));
        if (list_size(env, encrypted_row_bits) != static_cast<jint>(3 * row_bit_num)) {
            throw invalid_argument("CAPE flattened encrypted row bits size mismatch");
        }
        if (raw_matrix_rows.size() != static_cast<size_t>(packed_matrix_group_num * row_num)) {
            throw invalid_argument("encoded matrix size mismatch in global tiled fused score");
        }
        vector<vector<RGSWCipher>> row_bits(3);
        for (jint a = 0; a < 3; a++) {
            row_bits[a].reserve(row_bit_num);
            for (jint b = 0; b < row_bit_num; b++) {
                auto bit_bytes = reinterpret_cast<jbyteArray>(list_get(env, encrypted_row_bits, a * row_bit_num + b));
                row_bits[a].push_back(deserialize_rgsw(env, bit_bytes, context));
                env->DeleteLocalRef(bit_bytes);
            }
        }
        TFHEcipher tfhe(context, public_key);
        Encryptor encryptor(context, public_key);
        vector<Ciphertext> total_scores(static_cast<size_t>(max_value_num_per_keyword));
        vector<bool> total_score_initialized(static_cast<size_t>(max_value_num_per_keyword), false);
        for (jint group = 0; group < packed_matrix_group_num; group++) {
            Ciphertext group_reply;
            bool initialized = false;
            for (jint a = 0; a < 3; a++) {
                Ciphertext packed_col;
                bool packed_initialized = false;
                for (jint row = 0; row < row_num; row++) {
                    const Plaintext &raw_row = raw_matrix_rows[group * row_num + row];
                    if (raw_row.is_zero()) {
                        continue;
                    }
                    Plaintext matrix_row = build_shifted_matrix_row(
                        raw_row, parms, col_num, blocks_per_packed_matrix
                    );
                    if (matrix_row.is_zero()) {
                        continue;
                    }
                    Ciphertext selected;
                    evaluator.multiply_plain(queries[a], matrix_row, selected);
                    if (selected.is_transparent()) {
                        continue;
                    }
                    Ciphertext coeff_selected = selected;
                    if (row > 0) {
                        coeff_selected = mul_by_monomial(coeff_selected, row * row_stride, context);
                    }
                    if (!packed_initialized) {
                        packed_col = coeff_selected;
                        packed_initialized = true;
                    } else if (!coeff_selected.is_transparent()) {
                        evaluator.add_inplace(packed_col, coeff_selected);
                    }
                }
                if (!packed_initialized) {
                    continue;
                }
                Ciphertext rotated = blind_rotate_to_zero(
                    packed_col, row_bits[a], row_num, row_stride, context, tfhe, evaluator
                );
                if (!initialized) {
                    group_reply = rotated;
                    initialized = true;
                } else if (!rotated.is_transparent()) {
                    evaluator.add_inplace(group_reply, rotated);
                }
            }
            if (!initialized) {
                encryptor.encrypt_zero(group_reply);
            }
            if (group_reply.is_ntt_form()) {
                evaluator.transform_from_ntt_inplace(group_reply);
            }
            jint value_index = (group * blocks_per_packed_matrix) / bloom_bit_length;
            if (value_index >= max_value_num_per_keyword) {
                continue;
            }
            Ciphertext product;
            evaluator.multiply(group_reply, query_groups[group], product);
            evaluator.relinearize_inplace(product, relin_keys);
            if (!total_score_initialized[value_index]) {
                total_scores[value_index] = product;
                total_score_initialized[value_index] = true;
            } else if (!product.is_transparent()) {
                evaluator.add_inplace(total_scores[value_index], product);
            }
        }
        Ciphertext packed_score;
        bool packed_initialized = false;
        for (jint value_index = 0; value_index < max_value_num_per_keyword; value_index++) {
            if (!total_score_initialized[value_index]) {
                encryptor.encrypt_zero(total_scores[value_index]);
            }
            keep_constant_coefficient_inplace(evaluator, total_scores[value_index], *galois_keys, context);
            Ciphertext shifted_score = value_index == 0
                ? total_scores[value_index]
                : mul_by_monomial(total_scores[value_index], value_index, context);
            if (!packed_initialized) {
                packed_score = shifted_score;
                packed_initialized = true;
            } else if (!shifted_score.is_transparent()) {
                evaluator.add_inplace(packed_score, shifted_score);
            }
        }
        jobject scores = new_array_list(env);
        jbyteArray score_bytes = serialize_ciphertext(env, packed_score);
        list_add(env, scores, score_bytes);
        env->DeleteLocalRef(score_bytes);
        delete galois_keys;
        return scores;
    } catch (const exception &e) {
        if (galois_keys != nullptr) {
            delete galois_keys;
        }
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generateFusedPackedCoeffCtCtBloomScoresPackedBloom
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray pk_bytes, jbyteArray relin_keys_bytes,
     jbyteArray galois_keys_bytes, jobject column_queries, jobject encrypted_row_bits, jobject encoded_matrices,
     jobject encrypted_packed_bloom_queries, jint payload_block_num, jint row_num, jint col_num,
     jint bloom_matrix_column_capacity, jint query_blocks_per_packed_matrix, jint blocks_per_packed_matrix,
     jint max_value_num_per_keyword, jint bloom_bit_length) {
    GaloisKeys *galois_keys = nullptr;
    try {
        if (max_value_num_per_keyword <= 0 || payload_block_num <= 0 || row_num <= 0 || col_num <= 0
            || bloom_matrix_column_capacity <= 0 || query_blocks_per_packed_matrix <= 0
            || blocks_per_packed_matrix <= 0 || bloom_bit_length <= 0) {
            throw invalid_argument("invalid CAPE packed Bloom fused packed score parameters");
        }
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "CAPE", __func__);
        Evaluator evaluator(context);
        PublicKey public_key = deserialize_public_key(env, pk_bytes, context);
        RelinKeys relin_keys = deserialize_relin_keys(env, relin_keys_bytes, context);
        galois_keys = deserialize_galois_keys(env, galois_keys_bytes, context);
        vector<Ciphertext> queries = deserialize_ciphertexts(env, column_queries, context);
        vector<Ciphertext> packed_bloom_queries = deserialize_ciphertexts(env, encrypted_packed_bloom_queries, context);
        uint32_t coeff_count = parms.poly_modulus_degree();
        if (queries.size() != 3) {
            throw invalid_argument("CAPE packed Bloom fused score needs exactly three BFF position queries");
        }
        if (static_cast<size_t>(max_value_num_per_keyword) > coeff_count) {
            throw invalid_argument("maxValueNumPerKeyword exceeds score packing capacity");
        }
        if (bloom_bit_length > static_cast<jint>(coeff_count)) {
            throw invalid_argument("CAPE P10 packed Bloom payload requires bloomBitLength <= polyModulusDegree");
        }
        if (blocks_per_packed_matrix % bloom_bit_length != 0) {
            throw invalid_argument("CAPE P10 packed Bloom coefficient stride must be a multiple of bloomBitLength");
        }
        jint bloom_per_packed_block = blocks_per_packed_matrix / bloom_bit_length;
        if (bloom_per_packed_block <= 0) {
            throw invalid_argument("CAPE P10 packed Bloom coefficient stride cannot hold one Bloom filter");
        }
        jint expected_packed_payload_block_num = (max_value_num_per_keyword + bloom_per_packed_block - 1)
            / bloom_per_packed_block;
        if (payload_block_num != expected_packed_payload_block_num) {
            throw invalid_argument("CAPE P10 packed Bloom payload block count mismatch");
        }
        jint packed_matrix_group_num = payload_block_num;
        jint packed_query_bloom_num = (bloom_bit_length + static_cast<jint>(coeff_count) - 1)
            / static_cast<jint>(coeff_count);
        if (packed_bloom_queries.size() != static_cast<size_t>(packed_query_bloom_num)) {
            throw invalid_argument("CAPE packed Bloom formal query ciphertext count mismatch");
        }
        if (static_cast<uint64_t>(col_num) * static_cast<uint64_t>(query_blocks_per_packed_matrix) > coeff_count) {
            throw invalid_argument("CAPE packed Bloom query column stride exceeds polyModulusDegree");
        }
        jint column_tile_num = (col_num + bloom_matrix_column_capacity - 1) / bloom_matrix_column_capacity;
        if (static_cast<uint64_t>(bloom_matrix_column_capacity) * static_cast<uint64_t>(blocks_per_packed_matrix)
            > coeff_count) {
            throw invalid_argument("CAPE packed Bloom matrix column tile exceeds polyModulusDegree");
        }
        jint row_stride = blocks_per_packed_matrix;
        if (static_cast<uint64_t>(row_num) * static_cast<uint64_t>(row_stride) > coeff_count) {
            throw invalid_argument("CAPE packed matrix requires rowNum * rowStride <= polyModulusDegree");
        }
        jint row_bit_num = static_cast<jint>(ceil_log2(static_cast<uint32_t>(row_num)));
        if (list_size(env, encrypted_row_bits) != static_cast<jint>(3 * row_bit_num)) {
            throw invalid_argument("CAPE flattened encrypted row bits size mismatch");
        }
        jint encoded_matrix_size = list_size(env, encoded_matrices);
        if (encoded_matrix_size != packed_matrix_group_num * column_tile_num * row_num) {
            throw invalid_argument("encoded matrix size mismatch in packed Bloom fused score");
        }
        cerr << "[CAPE-CHECKPOINT] native packed Bloom score begin: packedMatrixGroupNum="
             << packed_matrix_group_num << ", rowNum=" << row_num << ", encodedMatrixRows="
             << encoded_matrix_size << ", maxValueNumPerKeyword=" << max_value_num_per_keyword
             << ", bloomBitLength=" << bloom_bit_length << ", bloomPerPackedBlock=" << bloom_per_packed_block
             << ", bloomMatrixColumnCapacity=" << bloom_matrix_column_capacity
             << ", bloomMatrixColumnTileNum=" << column_tile_num
             << ", queryBlocksPerPackedMatrix=" << query_blocks_per_packed_matrix
             << ", bloomBlocksPerPackedMatrix=" << blocks_per_packed_matrix
             << ", scoreExtractionLoopBound=maxValueNumPerKeyword" << endl;
        vector<vector<RGSWCipher>> row_bits(3);
        for (jint a = 0; a < 3; a++) {
            row_bits[a].reserve(row_bit_num);
            for (jint b = 0; b < row_bit_num; b++) {
                auto bit_bytes = reinterpret_cast<jbyteArray>(list_get(env, encrypted_row_bits, a * row_bit_num + b));
                row_bits[a].push_back(deserialize_rgsw(env, bit_bytes, context));
                env->DeleteLocalRef(bit_bytes);
            }
        }
        TFHEcipher tfhe(context, public_key);
        Encryptor encryptor(context, public_key);
        Ciphertext packed_score;
        bool packed_initialized = false;
        for (jint group = 0; group < packed_matrix_group_num; group++) {
            if (group == 0 || group + 1 == packed_matrix_group_num || group % 16 == 0) {
                cerr << "[CAPE-CHECKPOINT] native packed Bloom score group "
                     << (group + 1) << "/" << packed_matrix_group_num << endl;
            }
            Ciphertext group_reply;
            bool initialized = false;
            for (jint a = 0; a < 3; a++) {
                Ciphertext packed_col;
                bool packed_initialized = false;
                for (jint column_tile = 0; column_tile < column_tile_num; column_tile++) {
                    jint tile_start_col = column_tile * bloom_matrix_column_capacity;
                    jint tile_col_num = min(bloom_matrix_column_capacity, col_num - tile_start_col);
                    for (jint row = 0; row < row_num; row++) {
                        Plaintext raw_row = deserialize_plaintext_from_list(
                            env, encoded_matrices,
                            (group * column_tile_num + column_tile) * row_num + row, context
                        );
                        if (raw_row.is_zero()) {
                            continue;
                        }
                        Plaintext matrix_row = build_shifted_matrix_row_with_query_stride(
                            raw_row, parms, tile_col_num, tile_start_col, blocks_per_packed_matrix,
                            query_blocks_per_packed_matrix
                        );
                        if (matrix_row.is_zero()) {
                            continue;
                        }
                        Ciphertext selected;
                        evaluator.multiply_plain(queries[a], matrix_row, selected);
                        if (selected.is_transparent()) {
                            continue;
                        }
                        Ciphertext coeff_selected = selected;
                        if (row > 0) {
                            coeff_selected = mul_by_monomial(coeff_selected, row * row_stride, context);
                        }
                        if (!packed_initialized) {
                            packed_col = coeff_selected;
                            packed_initialized = true;
                        } else if (!coeff_selected.is_transparent()) {
                            evaluator.add_inplace(packed_col, coeff_selected);
                        }
                    }
                }
                if (!packed_initialized) {
                    continue;
                }
                Ciphertext rotated = blind_rotate_to_zero(
                    packed_col, row_bits[a], row_num, row_stride, context, tfhe, evaluator
                );
                if (!initialized) {
                    group_reply = rotated;
                    initialized = true;
                } else if (!rotated.is_transparent()) {
                    evaluator.add_inplace(group_reply, rotated);
                }
            }
            if (!initialized) {
                encryptor.encrypt_zero(group_reply);
            }
            if (group_reply.is_ntt_form()) {
                evaluator.transform_from_ntt_inplace(group_reply);
            }
            Ciphertext product;
            evaluator.multiply(group_reply, packed_bloom_queries[0], product);
            evaluator.relinearize_inplace(product, relin_keys);
            if (product.is_transparent()) {
                continue;
            }
            jint valid_candidate_windows = min(
                bloom_per_packed_block, max_value_num_per_keyword - group * bloom_per_packed_block
            );
            cerr << "[CAPE-CHECKPOINT] native P10 packed Bloom block " << (group + 1) << "/"
                 << packed_matrix_group_num << ": validCandidateWindows=" << valid_candidate_windows
                 << ", ignoredPaddingCoefficients=" << (coeff_count - valid_candidate_windows * bloom_bit_length)
                 << ", scoreExtractionLoopBound=" << valid_candidate_windows << endl;
            for (jint local_candidate = 0; local_candidate < valid_candidate_windows; local_candidate++) {
                jint global_candidate = group * bloom_per_packed_block + local_candidate;
                jint dot_coeff = local_candidate * bloom_bit_length;
                Ciphertext candidate_score = dot_coeff == 0
                    ? product
                    : mul_by_monomial(product, -dot_coeff, context);
                keep_constant_coefficient_inplace(evaluator, candidate_score, *galois_keys, context);
                Ciphertext shifted_score = global_candidate == 0
                    ? candidate_score
                    : mul_by_monomial(candidate_score, global_candidate, context);
                if (!packed_initialized) {
                    packed_score = shifted_score;
                    packed_initialized = true;
                } else if (!shifted_score.is_transparent()) {
                    evaluator.add_inplace(packed_score, shifted_score);
                }
            }
        }
        cerr << "[CAPE-CHECKPOINT] native packed Bloom score packing end" << endl;
        if (!packed_initialized) {
            encryptor.encrypt_zero(packed_score);
        }
        jobject scores = new_array_list(env);
        jbyteArray score_bytes = serialize_ciphertext(env, packed_score);
        list_add(env, scores, score_bytes);
        env->DeleteLocalRef(score_bytes);
        cerr << "[CAPE-CHECKPOINT] native packed Bloom score end" << endl;
        delete galois_keys;
        return scores;
    } catch (const exception &e) {
        if (galois_keys != nullptr) {
            delete galois_keys;
        }
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generateCoeffCtCtBloomInnerProductsFromBitReplies
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray pk_bytes, jbyteArray relin_keys_bytes,
     jobject encrypted_query_bloom_bits, jobject encrypted_candidate_bloom_bits,
     jint max_value_num_per_keyword, jint bloom_bit_length) {
    try {
        if (max_value_num_per_keyword <= 0 || bloom_bit_length <= 0) {
            throw invalid_argument("invalid CAPE bit-reply Bloom score parameters");
        }
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "CAPE", __func__);
        Evaluator evaluator(context);
        PublicKey public_key = deserialize_public_key(env, pk_bytes, context);
        Encryptor encryptor(context, public_key);
        RelinKeys relin_keys = deserialize_relin_keys(env, relin_keys_bytes, context);
        vector<Ciphertext> query_bits = deserialize_ciphertexts(env, encrypted_query_bloom_bits, context);
        vector<Ciphertext> candidate_bits = deserialize_ciphertexts(env, encrypted_candidate_bloom_bits, context);
        if (query_bits.size() != static_cast<size_t>(bloom_bit_length)) {
            throw invalid_argument("encrypted query Bloom bit size mismatch");
        }
        if (candidate_bits.size() != static_cast<size_t>(max_value_num_per_keyword * bloom_bit_length)) {
            throw invalid_argument("encrypted candidate Bloom bit size mismatch");
        }
        jobject scores = new_array_list(env);
        for (jint value_index = 0; value_index < max_value_num_per_keyword; value_index++) {
            Ciphertext score;
            encryptor.encrypt_zero(score);
            for (jint bit_index = 0; bit_index < bloom_bit_length; bit_index++) {
                Ciphertext product;
                evaluator.multiply(
                    candidate_bits[value_index * bloom_bit_length + bit_index],
                    query_bits[bit_index],
                    product
                );
                evaluator.relinearize_inplace(product, relin_keys);
                if (!product.is_transparent()) {
                    evaluator.add_inplace(score, product);
                }
            }
            jbyteArray score_bytes = serialize_ciphertext(env, score);
            list_add(env, scores, score_bytes);
            env->DeleteLocalRef(score_bytes);
        }
        return scores;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_splitCandidateItemCiphertext
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray encrypted_candidate_payload, jint item_index,
     jint fingerprint_byte_length, jint value_byte_length, jint bloom_byte_length, jint payload_item_byte_length) {
    try {
        if (item_index < 0 || fingerprint_byte_length < 0 || value_byte_length <= 0 || bloom_byte_length <= 0 ||
            payload_item_byte_length <= 0) {
            throw invalid_argument("invalid CAPE candidate item split parameters");
        }
        if (payload_item_byte_length != 1 + value_byte_length + bloom_byte_length) {
            throw invalid_argument("payloadItemByteLength must equal 1 + valueByteLength + bloomByteLength");
        }
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "CAPE", __func__);
        Evaluator evaluator(context);
        Ciphertext candidate_payload = deserialize_ciphertext(env, encrypted_candidate_payload, context);
        BatchEncoder encoder(context);
        size_t slot_count = encoder.slot_count();
        size_t item_offset = static_cast<size_t>(fingerprint_byte_length)
            + static_cast<size_t>(item_index) * static_cast<size_t>(payload_item_byte_length);
        size_t value_offset = item_offset + 1;
        size_t bloom_offset = value_offset + static_cast<size_t>(value_byte_length);
        size_t item_end = bloom_offset + static_cast<size_t>(bloom_byte_length);
        if (item_end > slot_count) {
            throw invalid_argument("candidate item exceeds BatchEncoder slot capacity");
        }
        vector<uint64_t> value_mask_slots(slot_count, 0ULL);
        for (jint i = 0; i < value_byte_length; i++) {
            value_mask_slots[value_offset + static_cast<size_t>(i)] = 1ULL;
        }
        Plaintext value_mask;
        encoder.encode(value_mask_slots, value_mask);
        vector<uint64_t> bloom_mask_slots(slot_count, 0ULL);
        for (jint i = 0; i < bloom_byte_length; i++) {
            bloom_mask_slots[bloom_offset + static_cast<size_t>(i)] = 1ULL;
        }
        Plaintext bloom_mask;
        encoder.encode(bloom_mask_slots, bloom_mask);
        Ciphertext encrypted_value;
        evaluator.multiply_plain(candidate_payload, value_mask, encrypted_value);
        Ciphertext encrypted_bloom;
        evaluator.multiply_plain(candidate_payload, bloom_mask, encrypted_bloom);
        vector<Ciphertext> result;
        result.push_back(encrypted_value);
        result.push_back(encrypted_bloom);
        return serialize_ciphertexts(env, result);
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generateReplyForTest
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray pk_bytes, jbyteArray galois_keys_bytes,
     jobject fusepirColumnQueries, jobject fusepirEncryptedRowBits, jobject encrypted_bloom_filter,
     jobject encodedFusePirMatrices, jobject encoded_value_bloom_filters, jint payloadBlockNum, jint rowNum,
     jint colNum, jint blocksPerPackedMatrix) {
    jobject value_payloads = Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generateFusePirCandidateReply(
        env, nullptr, parms_bytes, pk_bytes, fusepirColumnQueries, fusepirEncryptedRowBits, encodedFusePirMatrices,
        payloadBlockNum, rowNum, colNum, blocksPerPackedMatrix
    );
    if (env->ExceptionCheck()) {
        return nullptr;
    }
    jobject scores = Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generatePackedBloomInnerProductsForTest(
        env, nullptr, parms_bytes, pk_bytes, galois_keys_bytes, encrypted_bloom_filter, encoded_value_bloom_filters
    );
    if (env->ExceptionCheck()) {
        return nullptr;
    }
    jobject result = new_array_list(env);
    jint value_size = list_size(env, value_payloads);
    for (jint i = 0; i < value_size; i++) {
        jobject item = list_get(env, value_payloads, i);
        list_add(env, result, item);
        env->DeleteLocalRef(item);
    }
    jint score_size = list_size(env, scores);
    for (jint i = 0; i < score_size; i++) {
        jobject item = list_get(env, scores, i);
        list_add(env, result, item);
        env->DeleteLocalRef(item);
    }
    return result;
}

JNIEXPORT jlongArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_decryptReply
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray sk_bytes, jbyteArray response_bytes) {
    try {
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "CAPE", __func__);
        SecretKey secret_key = deserialize_secret_key(env, sk_bytes, context);
        Decryptor decryptor(context, secret_key);
        Ciphertext response = deserialize_ciphertext(env, response_bytes, context);
        if (decryptor.invariant_noise_budget(response) == 0) {
            throw invalid_argument("noise budget is 0");
        }
        BatchEncoder encoder(context);
        Plaintext plain;
        decryptor.decrypt(response, plain);
        vector<uint64_t> slots;
        encoder.decode(plain, slots);
        jlongArray result = env->NewLongArray(static_cast<jsize>(parms.poly_modulus_degree()));
        vector<jlong> output(parms.poly_modulus_degree());
        for (size_t i = 0; i < parms.poly_modulus_degree(); i++) {
            output[i] = static_cast<jlong>(slots[i]);
        }
        env->SetLongArrayRegion(result, 0, static_cast<jsize>(output.size()), output.data());
        return result;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jlongArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_decryptCoeffReply
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray sk_bytes, jbyteArray response_bytes) {
    try {
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "CAPE", __func__);
        SecretKey secret_key = deserialize_secret_key(env, sk_bytes, context);
        Decryptor decryptor(context, secret_key);
        Ciphertext response = deserialize_ciphertext(env, response_bytes, context);
        if (response.is_ntt_form()) {
            Evaluator evaluator(context);
            evaluator.transform_from_ntt_inplace(response);
        }
        if (decryptor.invariant_noise_budget(response) == 0) {
            throw invalid_argument("noise budget is 0");
        }
        Plaintext plain(parms.poly_modulus_degree());
        decryptor.decrypt(response, plain);
        jlongArray result = env->NewLongArray(static_cast<jsize>(parms.poly_modulus_degree()));
        vector<jlong> output(parms.poly_modulus_degree(), 0L);
        for (size_t i = 0; i < parms.poly_modulus_degree(); i++) {
            output[i] = i < plain.coeff_count() ? static_cast<jlong>(plain[i]) : 0L;
        }
        env->SetLongArrayRegion(result, 0, static_cast<jsize>(output.size()), output.data());
        return result;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jlongArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_decryptPackedScoreCoeffReply
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray sk_bytes, jbyteArray response_bytes) {
    try {
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "CAPE", __func__);
        SecretKey secret_key = deserialize_secret_key(env, sk_bytes, context);
        Decryptor decryptor(context, secret_key);
        Ciphertext response = deserialize_ciphertext(env, response_bytes, context);
        if (response.is_ntt_form()) {
            Evaluator evaluator(context);
            evaluator.transform_from_ntt_inplace(response);
        }
        Plaintext plain(parms.poly_modulus_degree());
        decryptor.decrypt(response, plain);
        jlongArray result = env->NewLongArray(static_cast<jsize>(parms.poly_modulus_degree()));
        vector<jlong> output(parms.poly_modulus_degree(), 0L);
        for (size_t i = 0; i < parms.poly_modulus_degree(); i++) {
            output[i] = i < plain.coeff_count() ? static_cast<jlong>(plain[i]) : 0L;
        }
        env->SetLongArrayRegion(result, 0, static_cast<jsize>(output.size()), output.data());
        return result;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jbyteArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_encryptCoeffPlain
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray pk_bytes, jlongArray coeffs) {
    try {
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "CAPE", __func__);
        PublicKey public_key = deserialize_public_key(env, pk_bytes, context);
        jint coeff_len = env->GetArrayLength(coeffs);
        if (static_cast<size_t>(coeff_len) > parms.poly_modulus_degree()) {
            throw invalid_argument("coeff array exceeds poly modulus degree");
        }
        jlong *ptr = env->GetLongArrayElements(coeffs, JNI_FALSE);
        Plaintext plain(parms.poly_modulus_degree());
        plain.set_zero();
        for (jint i = 0; i < coeff_len; i++) {
            plain[static_cast<size_t>(i)] = static_cast<uint64_t>(ptr[i]) % parms.plain_modulus().value();
        }
        env->ReleaseLongArrayElements(coeffs, ptr, JNI_ABORT);
        Encryptor encryptor(context, public_key);
        Ciphertext ciphertext;
        encryptor.encrypt(plain, ciphertext);
        return serialize_ciphertext(env, ciphertext);
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}
