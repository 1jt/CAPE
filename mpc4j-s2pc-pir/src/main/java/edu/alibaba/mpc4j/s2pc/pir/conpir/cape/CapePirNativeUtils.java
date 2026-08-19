package edu.alibaba.mpc4j.s2pc.pir.conpir.cape;

import edu.alibaba.mpc4j.common.tool.CommonConstants;

import java.util.List;

/**
 * CAPE PIR native utils.
 *
 * @author Weiran Liu
 * @date 2026/06/06
 */
class CapePirNativeUtils {
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
    /**
     * CAPE LWE dimension for compressed row-bit queries.
     */
    static final int LWE_DIMENSION = 32;
    /**
     * CAPE LWE modulus for compressed row-bit queries.
     */
    static final long LWE_MODULUS = 1L << 32;
    /**
     * message scale for compressed row-bit LWE bits.
     */
    static final long DELTA_BIT = 1L;

    static {
        System.loadLibrary(CommonConstants.MPC4J_NATIVE_FHE_NAME);
    }

    private CapePirNativeUtils() {
        // empty
    }

    static native byte[] generateEncryptionParams(int polyModulusDegree, long plainModulus, int[] coeffModulusBits);

    static native List<byte[]> keyGen(byte[] encryptionParams);

    static native byte[] generateColumnQuery(byte[] encryptionParams, byte[] publicKey, byte[] secretKey,
                                             int columnIndex, int columnNum);

    static native byte[] generatePackedColumnQuery(byte[] encryptionParams, byte[] publicKey, byte[] secretKey,
                                                   int columnIndex, int columnNum, int blocksPerPackedMatrix);

    static native List<byte[]> generateEncryptedRowBits(byte[] encryptionParams, byte[] publicKey, byte[] secretKey,
                                                        int rowIndex, int rowNum);

    static native List<byte[]> generateLweToRgswKey(byte[] encryptionParams, byte[] publicKey, long[] lweSecretKey);

    static native long createLweToRgswKeyHandle(byte[] encryptionParams, byte[] publicKey,
                                                List<byte[]> serializedLweToRgswKey);

    static native void destroyLweToRgswKeyHandle(long handle);

    static native List<byte[]> convertCompressedRowBitsToRgswWithHandle(byte[] encryptionParams, byte[] publicKey,
                                                                        long lweToRgswKeyHandle, long[][] aArray,
                                                                        long[] bArray);

    /**
     * Deprecated test-only conversion path. Formal server code must use native LWE-to-RGSW key handles.
     */
    @Deprecated
    static native List<byte[]> convertCompressedRowBitsToRgsw(byte[] encryptionParams, byte[] publicKey,
                                                              List<byte[]> lweToRgswKey, long[][] aArray,
                                                              long[] bArray);

    static native List<byte[]> generateEncryptedBloomFilter(byte[] encryptionParams, byte[] publicKey,
                                                            byte[] secretKey, long[] bloomBits);

    static native byte[] generateEncryptedCoeffBloomFilter(byte[] encryptionParams, byte[] publicKey,
                                                           byte[] secretKey, long[] bloomBits);

    /**
     * Legacy bit-by-bit query encryption helper. Real CAPE protocol code must use packed group Bloom queries instead.
     */
    @Deprecated
    static native List<byte[]> generateEncryptedCoeffBloomScalarBits(byte[] encryptionParams, byte[] publicKey,
                                                                     byte[] secretKey, long[] bloomBits);

    static native List<byte[]> encryptBloomFilter(byte[] encryptionParams, byte[] publicKey, long[] bloomBits);

    static native List<byte[]> preprocessDatabase(byte[] encryptionParams, long[][][] fusepirMatrices,
                                                  long[][] valueBloomFilters);

    static native List<byte[]> generateFusePirCandidateReply(byte[] encryptionParams, byte[] publicKey,
                                                          List<byte[]> fusepirColumnQueries,
                                                          List<byte[]> fusepirEncryptedRowBits,
                                                          List<byte[]> encodedFusePirMatrices, int payloadBlockNum,
                                                          int rowNum, int colNum, int blocksPerPackedMatrix);

    static native List<byte[]> mergePackedValueAndScoreReplies(byte[] encryptionParams,
                                                               List<byte[]> encryptedValuePayloads,
                                                               List<byte[]> encryptedScores,
                                                               int valuePayloadCoeffNum,
                                                               int scoreCoeffNum);

    /**
     * Computes scores as CtPt inner products against a plaintext global value-Bloom table. This does not match the CAPE
     * protocol because scores are not derived from encrypted candidate items. Keep this method only for legacy native
     * tests / performance comparison; real CAPE must use {@link #generateCtCtBloomInnerProducts(byte[], byte[], byte[],
     * byte[], List, List)}.
     */
    @Deprecated
    static native List<byte[]> generateBloomInnerProductsForTest(byte[] encryptionParams, byte[] publicKey,
                                                                 byte[] galoisKeys,
                                                                 List<byte[]> encryptedBloomFilter,
                                                                 List<byte[]> encodedValueBloomFilters);

    /**
     * Packed variant of {@link #generateBloomInnerProductsForTest(byte[], byte[], byte[], List, List)}. This is a
     * legacy CtPt/global-score path and must not be called by the real protocol.
     */
    @Deprecated
    static native List<byte[]> generatePackedBloomInnerProductsForTest(byte[] encryptionParams, byte[] publicKey,
                                                                       byte[] galoisKeys,
                                                                       List<byte[]> encryptedBloomFilter,
                                                                       List<byte[]> encodedValueBloomFilters);

    static native List<byte[]> generateCtCtBloomInnerProducts(byte[] encryptionParams, byte[] publicKey,
                                                              byte[] relinKeys, byte[] galoisKeys,
                                                              List<byte[]> encryptedQueryBloomFilter,
                                                              List<byte[]> encryptedCandidateBloomFilters);

    static native List<byte[]> generateCoeffCtCtBloomInnerProducts(byte[] encryptionParams, byte[] publicKey,
                                                                   byte[] relinKeys,
                                                                   byte[] encryptedCoeffQueryBloomFilter,
                                                                   byte[] encryptedCandidateBloomPayload,
                                                                   int maxValueNumPerKeyword,
                                                                   int bloomBitLength);

    static native List<byte[]> generateCoeffCtCtBloomInnerProductsFromGroups(byte[] encryptionParams,
                                                                             byte[] publicKey, byte[] relinKeys,
                                                                             byte[] encryptedCoeffQueryBloomFilter,
                                                                             List<byte[]> encryptedCandidateBloomGroups,
                                                                             int maxValueNumPerKeyword,
                                                                             int bloomBitLength,
                                                                             int blocksPerPackedMatrix);

    static native List<byte[]> generateCoeffCtCtBloomInnerProductsFromGroupQueries(byte[] encryptionParams,
                                                                                   byte[] publicKey, byte[] relinKeys,
                                                                                   List<byte[]> encryptedCoeffQueryBloomGroups,
                                                                                   List<byte[]> encryptedCandidateBloomGroups,
                                                                                   int maxValueNumPerKeyword);

    static native List<byte[]> generatePackedCoeffCtCtBloomInnerProductsFromGroupQueries(byte[] encryptionParams,
                                                                                         byte[] publicKey,
                                                                                         byte[] relinKeys,
                                                                                         byte[] galoisKeys,
                                                                                         List<byte[]> encryptedCoeffQueryBloomGroups,
                                                                                         List<byte[]> encryptedCandidateBloomGroups,
                                                                                         int maxValueNumPerKeyword);

    static native List<byte[]> generateFusedPackedCoeffCtCtBloomScores(byte[] encryptionParams,
                                                                        byte[] publicKey, byte[] relinKeys,
                                                                        byte[] galoisKeys,
                                                                        List<byte[]> fusepirColumnQueries,
                                                                        List<byte[]> fusepirEncryptedRowBits,
                                                                        List<byte[]> encodedBloomOnlyMatrices,
                                                                        List<byte[]> encryptedCoeffQueryBloomGroups,
                                                                        int payloadBlockNum, int rowNum, int colNum,
                                                                        int blocksPerPackedMatrix,
                                                                        int maxValueNumPerKeyword);

    static native List<byte[]> generateFusedPackedCoeffCtCtBloomScoresGlobalTiled(byte[] encryptionParams,
                                                                                  byte[] publicKey, byte[] relinKeys,
                                                                                  byte[] galoisKeys,
                                                                                  List<byte[]> fusepirColumnQueries,
                                                                                  List<byte[]> fusepirEncryptedRowBits,
                                                                                  List<byte[]> encodedBloomOnlyMatrices,
                                                                                  List<byte[]> encryptedCoeffQueryBloomGroups,
                                                                                  int payloadBlockNum, int rowNum,
                                                                                  int colNum,
                                                                                  int blocksPerPackedMatrix,
                                                                                  int maxValueNumPerKeyword,
                                                                                  int bloomBitLength);

    static native List<byte[]> generateFusedPackedCoeffCtCtBloomScoresPackedBloom(byte[] encryptionParams,
                                                                                  byte[] publicKey, byte[] relinKeys,
                                                                                  byte[] galoisKeys,
                                                                                  List<byte[]> fusepirColumnQueries,
                                                                                  List<byte[]> fusepirEncryptedRowBits,
                                                                                  List<byte[]> encodedBloomOnlyMatrices,
                                                                                  List<byte[]> encryptedPackedBloomQueries,
                                                                                  int payloadBlockNum, int rowNum,
                                                                                  int colNum,
                                                                                  int bloomMatrixColumnCapacity,
                                                                                  int columnQueryBlocksPerPackedMatrix,
                                                                                  int bloomBlocksPerPackedMatrix,
                                                                                  int maxValueNumPerKeyword,
                                                                                  int bloomBitLength);

    /**
     * Legacy bit-by-bit score helper. Real CAPE protocol code must use packed group CtCt inner products instead.
     */
    @Deprecated
    static native List<byte[]> generateCoeffCtCtBloomInnerProductsFromBitReplies(byte[] encryptionParams,
                                                                                 byte[] publicKey, byte[] relinKeys,
                                                                                 List<byte[]> encryptedQueryBloomBits,
                                                                                 List<byte[]> encryptedCandidateBloomBits,
                                                                                 int maxValueNumPerKeyword,
                                                                                 int bloomBitLength);

    static native List<byte[]> splitCandidateItemCiphertext(byte[] encryptionParams, byte[] encryptedCandidatePayload,
                                                            int itemIndex, int fingerprintByteLength,
                                                            int valueByteLength, int bloomByteLength,
                                                            int payloadItemByteLength);

    /**
     * Legacy combined reply helper that returns FUSE_PIR candidate payloads plus global CtPt scores. This does not implement
     * the corrected CAPE flow and must not be called by server protocol code.
     */
    @Deprecated
    static native List<byte[]> generateReplyForTest(byte[] encryptionParams, byte[] publicKey,
                                                    byte[] galoisKeys,
                                                    List<byte[]> fusepirColumnQueries,
                                                    List<byte[]> fusepirEncryptedRowBits,
                                                    List<byte[]> encryptedBloomFilter,
                                                    List<byte[]> encodedFusePirMatrices,
                                                    List<byte[]> encodedValueBloomFilters, int payloadBlockNum,
                                                    int rowNum, int colNum, int blocksPerPackedMatrix);

    static native long[] decryptReply(byte[] encryptionParams, byte[] secretKey, byte[] response);

    static native long[] decryptCoeffReply(byte[] encryptionParams, byte[] secretKey, byte[] response);

    static native long[] decryptPackedScoreCoeffReply(byte[] encryptionParams, byte[] secretKey, byte[] response);

    static native byte[] encryptCoeffPlain(byte[] encryptionParams, byte[] publicKey, long[] coeffs);
}
