package edu.alibaba.mpc4j.s2pc.pir.conpir.capec;

import edu.alibaba.mpc4j.common.tool.CommonConstants;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.List;

/**
 * CAPE_C PIR native utils.
 *
 * <p>Phase 3 reuses CAPE's BFV and LWE-to-RGSW native helpers. This wrapper intentionally does not expose CAPE column
 * query generation, so CAPE_C cannot fall back to the original CAPE anchor query shape.</p>
 *
 * @author Weiran Liu
 * @date 2026/07/07
 */
class CapeCPirNativeUtils {
    /**
     * secret key index.
     */
    static final int SECRET_KEY_INDEX = 0;
    /**
     * public key index.
     */
    static final int PUBLIC_KEY_INDEX = 1;
    /**
     * relinearization keys index.
     */
    static final int RELIN_KEYS_INDEX = 2;
    /**
     * galois keys index.
     */
    static final int GALOIS_KEYS_INDEX = 3;

    private static final Class<?> CAPE_NATIVE_CLASS = loadCapeNativeClass();

    static {
        System.loadLibrary(CommonConstants.MPC4J_NATIVE_FHE_NAME);
    }

    private CapeCPirNativeUtils() {
        // empty
    }

    static native byte[] generateEncryptionParams(int polyModulusDegree, long plainModulus, int[] coeffModulusBits);

    static List<byte[]> keyGen(byte[] encryptionParams) {
        return invoke("keyGen", new Class<?>[]{byte[].class}, encryptionParams);
    }

    static List<byte[]> generateLweToRgswKey(byte[] encryptionParams, byte[] publicKey, long[] lweSecretKey) {
        return invoke("generateLweToRgswKey",
            new Class<?>[]{byte[].class, byte[].class, long[].class},
            encryptionParams, publicKey, lweSecretKey);
    }

    static long createLweToRgswKeyHandle(byte[] encryptionParams, byte[] publicKey,
                                         List<byte[]> serializedLweToRgswKey) {
        return invoke("createLweToRgswKeyHandle",
            new Class<?>[]{byte[].class, byte[].class, List.class},
            encryptionParams, publicKey, serializedLweToRgswKey);
    }

    static void destroyLweToRgswKeyHandle(long handle) {
        invoke("destroyLweToRgswKeyHandle", new Class<?>[]{long.class}, handle);
    }

    static List<byte[]> convertCompressedBitsToRgswWithHandle(byte[] encryptionParams, byte[] publicKey,
                                                              long lweToRgswKeyHandle, long[][] aArray,
                                                              long[] bArray) {
        return invoke("convertCompressedRowBitsToRgswWithHandle",
            new Class<?>[]{byte[].class, byte[].class, long.class, long[][].class, long[].class},
            encryptionParams, publicKey, lweToRgswKeyHandle, aArray, bArray);
    }

    static byte[] generateEncryptedCoeffBloomFilter(byte[] encryptionParams, byte[] publicKey,
                                                    byte[] secretKey, long[] bloomBits) {
        return invoke("generateEncryptedCoeffBloomFilter",
            new Class<?>[]{byte[].class, byte[].class, byte[].class, long[].class},
            encryptionParams, publicKey, secretKey, bloomBits);
    }

    static long[] decryptCoeffReply(byte[] encryptionParams, byte[] secretKey, byte[] response) {
        return invoke("decryptCoeffReply", new Class<?>[]{byte[].class, byte[].class, byte[].class},
            encryptionParams, secretKey, response);
    }

    static List<byte[]> preprocessDatabase(byte[] encryptionParams, long[][][] capecMatrices) {
        return invoke("preprocessDatabase", new Class<?>[]{byte[].class, long[][][].class, long[][].class},
            encryptionParams, capecMatrices, new long[0][]);
    }

    static native List<byte[]> generateCapeCCandidateReply(byte[] encryptionParams, byte[] publicKey,
                                                          List<byte[]> colRgswBits, List<byte[]> rowRgswBits,
                                                          List<byte[]> encodedValueOnlyMatrices,
                                                          int payloadBlockNum, int rowNum, int colNum,
                                                          int blocksPerPackedMatrix);

    static native List<byte[]> generateCapeCFusedPackedCoeffCtCtBloomScoresPackedBloom(byte[] encryptionParams,
                                                                                      byte[] publicKey,
                                                                                      byte[] relinKeys,
                                                                                      byte[] galoisKeys,
                                                                                      List<byte[]> colRgswBits,
                                                                                      List<byte[]> rowRgswBits,
                                                                                      List<byte[]> encodedBloomOnlyMatrices,
                                                                                      List<byte[]> encryptedPackedBloomQueries,
                                                                                      int payloadBlockNum,
                                                                                      int rowNum,
                                                                                      int colNum,
                                                                                      int bloomMatrixColumnCapacity,
                                                                                      int queryBlocksPerPackedMatrix,
                                                                                      int bloomBlocksPerPackedMatrix,
                                                                                      int maxValueNumPerKeyword,
                                                                                      int bloomBitLength);

    static List<byte[]> mergePackedValueAndScoreReplies(byte[] encryptionParams, List<byte[]> encryptedValuePayloads,
                                                        List<byte[]> encryptedScores, int valuePayloadCoeffNum,
                                                        int scoreCoeffNum) {
        return invoke("mergePackedValueAndScoreReplies",
            new Class<?>[]{byte[].class, List.class, List.class, int.class, int.class},
            encryptionParams, encryptedValuePayloads, encryptedScores, valuePayloadCoeffNum, scoreCoeffNum);
    }

    @SuppressWarnings("unchecked")
    private static <T> T invoke(String methodName, Class<?>[] parameterTypes, Object... args) {
        try {
            Method method = CAPE_NATIVE_CLASS.getDeclaredMethod(methodName, parameterTypes);
            method.setAccessible(true);
            return (T) method.invoke(null, args);
        } catch (NoSuchMethodException | IllegalAccessException e) {
            throw new IllegalStateException("Cannot access CAPE native helper: " + methodName, e);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException runtimeException) {
                throw runtimeException;
            }
            if (cause instanceof Error error) {
                throw error;
            }
            throw new IllegalStateException("CAPE native helper failed: " + methodName, cause);
        }
    }

    private static Class<?> loadCapeNativeClass() {
        try {
            return Class.forName("edu.alibaba.mpc4j.s2pc.pir.conpir.cape.CapePirNativeUtils");
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException("CAPE native utils are not available for CAPE_C", e);
        }
    }
}
