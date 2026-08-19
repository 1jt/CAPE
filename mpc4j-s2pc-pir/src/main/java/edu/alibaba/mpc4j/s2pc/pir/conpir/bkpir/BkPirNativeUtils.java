package edu.alibaba.mpc4j.s2pc.pir.conpir.bkpir;

import edu.alibaba.mpc4j.common.tool.CommonConstants;

import java.util.List;

/**
 * BKPIR native utils.
 *
 * @author Weiran Liu
 * @date 2026/06/05
 */
class BkPirNativeUtils {
    /**
     * keyGen result index: secret key.
     */
    static final int SECRET_KEY_INDEX = 0;
    /**
     * keyGen result index: public key.
     */
    static final int PUBLIC_KEY_INDEX = 1;
    /**
     * keyGen result index: relinearization keys.
     */
    static final int RELIN_KEYS_INDEX = 2;
    /**
     * keyGen result index: Galois keys.
     */
    static final int GALOIS_KEYS_INDEX = 3;

    static {
        System.loadLibrary(CommonConstants.MPC4J_NATIVE_FHE_NAME);
    }

    private BkPirNativeUtils() {
        // empty
    }

    static native byte[] generateEncryptionParams(int polyModulusDegree, long plainModulus, int[] coeffModulusBits);

    static native List<byte[]> keyGen(byte[] encryptionParams);

    static native byte[] generateQuery(byte[] encryptionParams, byte[] publicKey, byte[] secretKey,
                                       long[] queryCodeword);

    static native List<byte[]> preprocessDatabase(byte[] encryptionParams, long[][] keywordCodewords,
                                                  long[][] valueMaps, long[][] valuePayloads);

    static native List<byte[]> generateAndReply(byte[] encryptionParams, byte[] publicKey, byte[] relinKeys,
                                                byte[] galoisKeys, List<byte[]> queries,
                                                List<byte[]> encodedKeywordCodewords, List<byte[]> encodedValueMaps,
                                                List<byte[]> encodedValuePayloads, int cwWeight);

    static native List<byte[]> generateOrReply(byte[] encryptionParams, byte[] publicKey, byte[] relinKeys,
                                               byte[] galoisKeys, List<byte[]> queries,
                                               List<byte[]> encodedKeywordCodewords, List<byte[]> encodedValueMaps,
                                               List<byte[]> encodedValuePayloads, int cwWeight);

    static native List<byte[]> generateNotReply(byte[] encryptionParams, byte[] publicKey, byte[] relinKeys,
                                                byte[] galoisKeys, List<byte[]> queries,
                                                List<byte[]> encodedKeywordCodewords, List<byte[]> encodedValueMaps,
                                                List<byte[]> encodedValuePayloads, int cwWeight);

    static native long[] decryptReply(byte[] encryptionParams, byte[] secretKey, byte[] response);
}
