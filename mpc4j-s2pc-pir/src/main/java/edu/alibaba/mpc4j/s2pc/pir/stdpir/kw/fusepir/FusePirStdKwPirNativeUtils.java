package edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepir;

import edu.alibaba.mpc4j.common.tool.CommonConstants;

import java.util.List;

/**
 * FUSE_PIR standard keyword PIR native utils.
 *
 * @author Weiran Liu
 * @date 2026/06/05
 */
class FusePirStdKwPirNativeUtils {
    /**
     * secret key index
     */
    static final int SECRET_KEY_INDEX = 0;
    /**
     * public key index
     */
    static final int PUBLIC_KEY_INDEX = 1;
    /**
     * keyGen returns only secret/public keys. FUSE_PIR BlindRotate obtains RGSW row-bit ciphertexts by converting the
     * online compressed LWE row-bit query with the setup-time LWE-to-RGSW evaluation key.
     */
    static {
        System.loadLibrary(CommonConstants.MPC4J_NATIVE_FHE_NAME);
    }

    private FusePirStdKwPirNativeUtils() {
        // empty
    }

    static native byte[] generateEncryptionParams(int polyModulusDegree, long plainModulus, int[] coeffModulusBits);

    static native List<byte[]> keyGen(byte[] encryptionParams);

    static native byte[] generateColumnQuery(byte[] encryptionParams, byte[] publicKey, byte[] secretKey,
                                             int columnIndex, int columnNum);

    static native List<byte[]> generateEncryptedRowBits(byte[] encryptionParams, byte[] publicKey, byte[] secretKey,
                                                        int rowIndex, int rowNum);

    static native List<byte[]> generateLweToRgswKey(byte[] encryptionParams, byte[] publicKey, long[] lweSecretKey);

    static native List<byte[]> convertCompressedRowBitsToRgsw(byte[] encryptionParams, byte[] publicKey,
                                                              List<byte[]> lweToRgswKey, long[][] aArray,
                                                              long[] bArray);

    static native List<byte[]> preprocessDatabase(byte[] encryptionParams, long[][][] matrices, int colNum,
                                                  int blocksPerPackedMatrix);

    static native List<byte[]> generateReply(byte[] encryptionParams, byte[] publicKey, List<byte[]> columnQueries,
                                             List<byte[]> encryptedRowBits, List<byte[]> encodedMatrices,
                                             int payloadBlockNum, int rowNum, int colNum,
                                             int blocksPerPackedMatrix);

    static native long[][] decryptReply(byte[] encryptionParams, byte[] secretKey, List<byte[]> response);
}
