#include <jni.h>

#ifndef _Included_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepir_FusePirStdKwPirNativeUtils
#define _Included_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepir_FusePirStdKwPirNativeUtils
#ifdef __cplusplus
extern "C" {
#endif

JNIEXPORT jbyteArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepir_FusePirStdKwPirNativeUtils_generateEncryptionParams
    (JNIEnv *, jclass, jint, jlong, jintArray);

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepir_FusePirStdKwPirNativeUtils_keyGen
    (JNIEnv *, jclass, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepir_FusePirStdKwPirNativeUtils_generateColumnQuery
    (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray, jint, jint);

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepir_FusePirStdKwPirNativeUtils_generateEncryptedRowBits
    (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray, jint, jint);

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepir_FusePirStdKwPirNativeUtils_generateLweToRgswKey
    (JNIEnv *, jclass, jbyteArray, jbyteArray, jlongArray);

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepir_FusePirStdKwPirNativeUtils_convertCompressedRowBitsToRgsw
    (JNIEnv *, jclass, jbyteArray, jbyteArray, jobject, jobjectArray, jlongArray);

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepir_FusePirStdKwPirNativeUtils_preprocessDatabase
    (JNIEnv *, jclass, jbyteArray, jobjectArray, jint, jint);

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepir_FusePirStdKwPirNativeUtils_generateReply
    (JNIEnv *, jclass, jbyteArray, jbyteArray, jobject, jobject, jobject, jint, jint, jint, jint);

JNIEXPORT jobjectArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepir_FusePirStdKwPirNativeUtils_decryptReply
    (JNIEnv *, jclass, jbyteArray, jbyteArray, jobject);

#ifdef __cplusplus
}
#endif
#endif
