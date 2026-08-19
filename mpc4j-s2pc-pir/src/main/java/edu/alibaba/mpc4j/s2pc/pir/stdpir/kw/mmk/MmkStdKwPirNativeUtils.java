package edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.mmk;

import edu.alibaba.mpc4j.common.tool.CommonConstants;

import java.util.List;

/**
 * MMK standard keyword PIR native utils.
 *
 * @author Weiran Liu
 * @date 2026/06/04
 */
class MmkStdKwPirNativeUtils {
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

    private MmkStdKwPirNativeUtils() {
        // empty
    }

    /**
     * generate encryption params.
     *
     * @param polyModulusDegree poly modulus degree.
     * @param plainModulus      plain modulus.
     * @param coeffModulusBits  coeff modulus bits.
     * @return encryption params.
     */
    static native byte[] generateEncryptionParams(int polyModulusDegree, long plainModulus, int[] coeffModulusBits);

    /**
     * generate key pair. The return order is:
     * <ul>
     *     <li>[0] secret key</li>
     *     <li>[1] public key</li>
     *     <li>[2] relinearization keys</li>
     *     <li>[3] Galois keys</li>
     * </ul>
     *
     * @param encryptionParams encryption params.
     * @return key pair.
     */
    static native List<byte[]> keyGen(byte[] encryptionParams);

    /**
     * generate encrypted query.
     *
     * @param encryptionParams encryption params.
     * @param publicKey        public key.
     * @param secretKey        secret key.
     * @param queryCodeword    query codeword.
     * @return encrypted query.
     */
    static native byte[] generateQuery(byte[] encryptionParams, byte[] publicKey, byte[] secretKey, long[] queryCodeword);

    /**
     * preprocess database for MMKPIR response generation. The first n returned plaintexts encode keyword codewords,
     * and the next n returned plaintexts encode payloads.
     *
     * @param encryptionParams  encryption params.
     * @param keywordCodewords  keyword codewords.
     * @param payloadPlaintexts payload plaintexts.
     * @return encoded database plaintexts.
     */
    static native List<byte[]> preprocessDatabase(byte[] encryptionParams, long[][] keywordCodewords,
                                                  long[][] payloadPlaintexts);

    /**
     * generate server reply.
     *
     * @param encryptionParams       encryption params.
     * @param publicKey              public key.
     * @param relinKeys              relinearization keys.
     * @param galoisKeys             Galois keys.
     * @param query                  encrypted query.
     * @param encodedKeywordCodewords encoded keyword codewords.
     * @param encodedPayloads        encoded payloads.
     * @param cwWeight               constant weight.
     * @return encrypted replies, one ciphertext for each payload plaintext block.
     */
    static native List<byte[]> generateReply(byte[] encryptionParams, byte[] publicKey, byte[] relinKeys,
                                             byte[] galoisKeys, byte[] query, List<byte[]> encodedKeywordCodewords,
                                             List<byte[]> encodedPayloads, int payloadPlaintextNum, int cwWeight);

    /**
     * decrypt server reply.
     *
     * @param encryptionParams encryption params.
     * @param secretKey        secret key.
     * @param response         encrypted response.
     * @return decrypted coefficients.
     */
    static native long[] decryptReply(byte[] encryptionParams, byte[] secretKey, byte[] response);
}
