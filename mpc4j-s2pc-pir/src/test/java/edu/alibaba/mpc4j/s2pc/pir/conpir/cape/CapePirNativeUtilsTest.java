package edu.alibaba.mpc4j.s2pc.pir.conpir.cape;

import org.junit.Assert;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

/**
 * CAPE native utils test.
 *
 * @author Weiran Liu
 * @date 2026/06/06
 */
public class CapePirNativeUtilsTest {
    /**
     * poly modulus degree.
     */
    private static final int POLY_MODULUS_DEGREE = 8192;
    /**
     * plain modulus.
     */
    private static final long PLAIN_MODULUS = 65537L;
    /**
     * coeff modulus bits.
     */
    private static final int[] COEFF_MODULUS_BITS = new int[]{30, 30, 30, 30};
    /**
     * Bloom bit length.
     */
    private static final int BLOOM_BIT_LENGTH = 16;

    @Test
    public void testNativeBloomInnerProductForTestCtPtPath() {
        long[] queryBits = new long[BLOOM_BIT_LENGTH];
        queryBits[1] = 1L;
        queryBits[3] = 1L;
        queryBits[5] = 1L;
        queryBits[7] = 1L;
        long[] valueBits = queryBits.clone();
        long score = computeBloomInnerProduct(queryBits, valueBits);
        Assert.assertEquals(4L, score);
    }

    @Test
    public void testNativeBloomInnerProductMismatchForTestCtPtPath() {
        long[] queryBits = new long[BLOOM_BIT_LENGTH];
        queryBits[1] = 1L;
        queryBits[3] = 1L;
        queryBits[5] = 1L;
        queryBits[7] = 1L;
        long[] valueBits = queryBits.clone();
        valueBits[5] = 0L;
        long score = computeBloomInnerProduct(queryBits, valueBits);
        Assert.assertNotEquals(4L, score);
        Assert.assertEquals(3L, score);
    }

    @Test
    public void testNativePackedBloomInnerProductsForTestCtPtPath() {
        byte[] encryptionParams = CapePirNativeUtils.generateEncryptionParams(
            POLY_MODULUS_DEGREE, PLAIN_MODULUS, COEFF_MODULUS_BITS
        );
        List<byte[]> keyPair = CapePirNativeUtils.keyGen(encryptionParams);
        long[] queryBits = new long[BLOOM_BIT_LENGTH];
        queryBits[1] = 1L;
        queryBits[3] = 1L;
        queryBits[5] = 1L;
        queryBits[7] = 1L;
        List<byte[]> encryptedBloomFilter = CapePirNativeUtils.generateEncryptedBloomFilter(
            encryptionParams,
            keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX),
            keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX),
            queryBits
        );
        long[] fullMatch = queryBits.clone();
        long[] partialMatch = queryBits.clone();
        partialMatch[5] = 0L;
        long[] noMatch = new long[BLOOM_BIT_LENGTH];
        noMatch[2] = 1L;
        long[][] valueBloomFilters = new long[][]{fullMatch, partialMatch, noMatch};
        List<byte[]> encodedValueBloomFilters = CapePirNativeUtils.preprocessDatabase(
            encryptionParams, new long[0][][], valueBloomFilters
        );
        List<byte[]> scores = CapePirNativeUtils.generatePackedBloomInnerProductsForTest(
            encryptionParams,
            keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX),
            keyPair.get(CapePirNativeUtils.GALOIS_KEYS_INDEX),
            encryptedBloomFilter,
            encodedValueBloomFilters
        );
        Assert.assertEquals(1, scores.size());
        long[] packedScores = CapePirNativeUtils.decryptReply(
            encryptionParams, keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX), scores.get(0)
        );
        Assert.assertEquals(4L, packedScores[0]);
        Assert.assertEquals(3L, packedScores[1]);
        Assert.assertEquals(0L, packedScores[2]);
    }

    @Test
    public void testNativePackedBloomInnerProductsWithLargeBloomForTestCtPtPath() {
        byte[] encryptionParams = CapePirNativeUtils.generateEncryptionParams(
            POLY_MODULUS_DEGREE, PLAIN_MODULUS, COEFF_MODULUS_BITS
        );
        List<byte[]> keyPair = CapePirNativeUtils.keyGen(encryptionParams);
        long[] queryBits = new long[POLY_MODULUS_DEGREE + 16];
        queryBits[1] = 1L;
        queryBits[POLY_MODULUS_DEGREE - 1] = 1L;
        queryBits[POLY_MODULUS_DEGREE] = 1L;
        queryBits[POLY_MODULUS_DEGREE + 7] = 1L;
        List<byte[]> encryptedBloomFilter = CapePirNativeUtils.generateEncryptedBloomFilter(
            encryptionParams,
            keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX),
            keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX),
            queryBits
        );
        Assert.assertEquals(2, encryptedBloomFilter.size());
        long[] fullMatch = queryBits.clone();
        long[] partialMatch = queryBits.clone();
        partialMatch[POLY_MODULUS_DEGREE] = 0L;
        long[][] valueBloomFilters = new long[][]{fullMatch, partialMatch};
        List<byte[]> encodedValueBloomFilters = CapePirNativeUtils.preprocessDatabase(
            encryptionParams, new long[0][][], valueBloomFilters
        );
        Assert.assertEquals(4, encodedValueBloomFilters.size());
        List<byte[]> scores = CapePirNativeUtils.generatePackedBloomInnerProductsForTest(
            encryptionParams,
            keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX),
            keyPair.get(CapePirNativeUtils.GALOIS_KEYS_INDEX),
            encryptedBloomFilter,
            encodedValueBloomFilters
        );
        Assert.assertEquals(1, scores.size());
        long[] packedScores = CapePirNativeUtils.decryptReply(
            encryptionParams, keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX), scores.get(0)
        );
        Assert.assertEquals(4L, packedScores[0]);
        Assert.assertEquals(3L, packedScores[1]);
    }

    @Test
    public void testCapePackedColumnMatrixLayoutRowNumOne() {
        byte[] encryptionParams = CapePirNativeUtils.generateEncryptionParams(
            CapePirParams.DEFAULT_PARAMS.getPolyModulusDegree(),
            CapePirParams.DEFAULT_PARAMS.getPlainModulus(),
            CapePirParams.DEFAULT_PARAMS.getCoeffModulusBits()
        );
        List<byte[]> keyPair = CapePirNativeUtils.keyGen(encryptionParams);
        int rowNum = 1;
        int colNum = 4;
        int blocksPerPackedMatrix = 3;
        int payloadBlockNum = 3;
        int selectedCol = 2;
        long[][][] matrices = new long[1][rowNum][colNum * blocksPerPackedMatrix];
        matrices[0][0][selectedCol * blocksPerPackedMatrix] = 137L;
        matrices[0][0][selectedCol * blocksPerPackedMatrix + 1] = 138L;
        matrices[0][0][selectedCol * blocksPerPackedMatrix + 2] = 139L;
        List<byte[]> encodedMatrices = CapePirNativeUtils.preprocessDatabase(
            encryptionParams, matrices, new long[0][]
        );
        List<byte[]> columnQueries = List.of(
            CapePirNativeUtils.generatePackedColumnQuery(
                encryptionParams, keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX),
                keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX), selectedCol, colNum, blocksPerPackedMatrix
            ),
            CapePirNativeUtils.generatePackedColumnQuery(
                encryptionParams, keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX),
                keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX), 0, colNum, blocksPerPackedMatrix
            ),
            CapePirNativeUtils.generatePackedColumnQuery(
                encryptionParams, keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX),
                keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX), 1, colNum, blocksPerPackedMatrix
            )
        );
        List<byte[]> replies = CapePirNativeUtils.generateFusePirCandidateReply(
            encryptionParams, keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX), columnQueries, List.of(),
            encodedMatrices, payloadBlockNum, rowNum, colNum, blocksPerPackedMatrix
        );
        Assert.assertEquals(1, replies.size());
        long[] coeffs = CapePirNativeUtils.decryptCoeffReply(
            encryptionParams, keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX), replies.get(0)
        );
        Assert.assertEquals(137L, coeffs[0]);
        Assert.assertEquals(138L, coeffs[1]);
        Assert.assertEquals(139L, coeffs[2]);
    }

    @Test
    public void testCapeDirectRowBitsSelectPackedRow() {
        byte[] encryptionParams = CapePirNativeUtils.generateEncryptionParams(
            CapePirParams.DEFAULT_PARAMS.getPolyModulusDegree(),
            CapePirParams.DEFAULT_PARAMS.getPlainModulus(),
            CapePirParams.DEFAULT_PARAMS.getCoeffModulusBits()
        );
        List<byte[]> keyPair = CapePirNativeUtils.keyGen(encryptionParams);
        int rowNum = 4;
        int colNum = 4;
        int blocksPerPackedMatrix = 3;
        int payloadBlockNum = 3;
        int selectedRow = 2;
        int selectedCol = 2;
        long[][][] matrices = new long[1][rowNum][colNum * blocksPerPackedMatrix];
        matrices[0][selectedRow][selectedCol * blocksPerPackedMatrix] = 137L;
        matrices[0][selectedRow][selectedCol * blocksPerPackedMatrix + 1] = 138L;
        matrices[0][selectedRow][selectedCol * blocksPerPackedMatrix + 2] = 139L;
        matrices[0][1][selectedCol * blocksPerPackedMatrix] = 251L;
        List<byte[]> encodedMatrices = CapePirNativeUtils.preprocessDatabase(
            encryptionParams, matrices, new long[0][]
        );
        List<byte[]> columnQueries = List.of(
            CapePirNativeUtils.generatePackedColumnQuery(
                encryptionParams, keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX),
                keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX), selectedCol, colNum, blocksPerPackedMatrix
            ),
            CapePirNativeUtils.generatePackedColumnQuery(
                encryptionParams, keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX),
                keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX), 0, colNum, blocksPerPackedMatrix
            ),
            CapePirNativeUtils.generatePackedColumnQuery(
                encryptionParams, keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX),
                keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX), 1, colNum, blocksPerPackedMatrix
            )
        );
        List<byte[]> rowBits = new ArrayList<>();
        List<byte[]> selectedRowBits = CapePirNativeUtils.generateEncryptedRowBits(
            encryptionParams, keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX),
            keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX), selectedRow, rowNum
        );
        rowBits.addAll(selectedRowBits);
        rowBits.addAll(selectedRowBits);
        rowBits.addAll(selectedRowBits);
        List<byte[]> replies = CapePirNativeUtils.generateFusePirCandidateReply(
            encryptionParams, keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX), columnQueries, rowBits,
            encodedMatrices, payloadBlockNum, rowNum, colNum, blocksPerPackedMatrix
        );
        Assert.assertEquals(1, replies.size());
        long[] coeffs = CapePirNativeUtils.decryptCoeffReply(
            encryptionParams, keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX), replies.get(0)
        );
        Assert.assertEquals(137L, coeffs[0]);
        Assert.assertEquals(138L, coeffs[1]);
        Assert.assertEquals(139L, coeffs[2]);
    }

    @Test
    public void testNativeCtCtBloomInnerProductMatch() {
        long[] queryBits = new long[BLOOM_BIT_LENGTH];
        queryBits[1] = 1L;
        queryBits[3] = 1L;
        queryBits[5] = 1L;
        queryBits[7] = 1L;
        long[] valueBits = queryBits.clone();
        valueBits[9] = 1L;
        long score = computeCtCtBloomInnerProduct(queryBits, valueBits);
        Assert.assertEquals(4L, score);
    }

    @Test
    public void testNativeCtCtBloomInnerProductMismatch() {
        long[] queryBits = new long[BLOOM_BIT_LENGTH];
        queryBits[1] = 1L;
        queryBits[3] = 1L;
        queryBits[5] = 1L;
        queryBits[7] = 1L;
        long[] valueBits = queryBits.clone();
        valueBits[5] = 0L;
        long score = computeCtCtBloomInnerProduct(queryBits, valueBits);
        Assert.assertEquals(3L, score);
        Assert.assertNotEquals(4L, score);
    }

    @Test
    public void testNativeCoeffCtCtBloomInnerProductMatch() {
        byte[] encryptionParams = CapePirNativeUtils.generateEncryptionParams(
            POLY_MODULUS_DEGREE, PLAIN_MODULUS, COEFF_MODULUS_BITS
        );
        List<byte[]> keyPair = CapePirNativeUtils.keyGen(encryptionParams);
        long[] queryBits = new long[BLOOM_BIT_LENGTH];
        queryBits[1] = 1L;
        queryBits[3] = 1L;
        queryBits[5] = 1L;
        queryBits[7] = 1L;
        long[] candidatePayload = new long[2 * BLOOM_BIT_LENGTH];
        System.arraycopy(queryBits, 0, candidatePayload, 0, BLOOM_BIT_LENGTH);
        candidatePayload[9] = 1L;
        byte[] encryptedQuery = CapePirNativeUtils.generateEncryptedCoeffBloomFilter(
            encryptionParams,
            keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX),
            keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX),
            queryBits
        );
        byte[] encryptedCandidate = CapePirNativeUtils.encryptCoeffPlain(
            encryptionParams, keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX), candidatePayload
        );
        List<byte[]> scores = CapePirNativeUtils.generateCoeffCtCtBloomInnerProducts(
            encryptionParams,
            keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX),
            keyPair.get(CapePirNativeUtils.RELIN_KEYS_INDEX),
            encryptedQuery,
            encryptedCandidate,
            2,
            BLOOM_BIT_LENGTH
        );
        Assert.assertEquals(2, scores.size());
        long[] score0 = CapePirNativeUtils.decryptCoeffReply(
            encryptionParams, keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX), scores.get(0)
        );
        Assert.assertEquals(4L, score0[0]);
    }

    @Test
    public void testNativeGroupedCoeffCtCtBloomInnerProductMatch() {
        byte[] encryptionParams = CapePirNativeUtils.generateEncryptionParams(
            POLY_MODULUS_DEGREE, PLAIN_MODULUS, COEFF_MODULUS_BITS
        );
        List<byte[]> keyPair = CapePirNativeUtils.keyGen(encryptionParams);
        long[] queryBits = new long[BLOOM_BIT_LENGTH];
        queryBits[1] = 1L;
        queryBits[3] = 1L;
        queryBits[5] = 1L;
        queryBits[7] = 1L;
        long[] candidatePayload = new long[2 * BLOOM_BIT_LENGTH];
        System.arraycopy(queryBits, 0, candidatePayload, 0, BLOOM_BIT_LENGTH);
        candidatePayload[9] = 1L;
        candidatePayload[BLOOM_BIT_LENGTH + 1] = 1L;
        candidatePayload[BLOOM_BIT_LENGTH + 3] = 1L;
        candidatePayload[BLOOM_BIT_LENGTH + 7] = 1L;
        int blocksPerPackedMatrix = 5;
        int groupNum = (candidatePayload.length + blocksPerPackedMatrix - 1) / blocksPerPackedMatrix;
        List<byte[]> encryptedGroups = new ArrayList<>(groupNum);
        for (int groupIndex = 0; groupIndex < groupNum; groupIndex++) {
            long[] groupPayload = new long[blocksPerPackedMatrix];
            int copyLength = Math.min(blocksPerPackedMatrix, candidatePayload.length - groupIndex * blocksPerPackedMatrix);
            System.arraycopy(candidatePayload, groupIndex * blocksPerPackedMatrix, groupPayload, 0, copyLength);
            encryptedGroups.add(CapePirNativeUtils.encryptCoeffPlain(
                encryptionParams, keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX), groupPayload
            ));
        }
        byte[] encryptedQuery = CapePirNativeUtils.generateEncryptedCoeffBloomFilter(
            encryptionParams,
            keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX),
            keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX),
            queryBits
        );
        List<byte[]> scores = CapePirNativeUtils.generateCoeffCtCtBloomInnerProductsFromGroups(
            encryptionParams,
            keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX),
            keyPair.get(CapePirNativeUtils.RELIN_KEYS_INDEX),
            encryptedQuery,
            encryptedGroups,
            2,
            BLOOM_BIT_LENGTH,
            blocksPerPackedMatrix
        );
        Assert.assertEquals(2, scores.size());
        long[] score0 = CapePirNativeUtils.decryptCoeffReply(
            encryptionParams, keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX), scores.get(0)
        );
        long[] score1 = CapePirNativeUtils.decryptCoeffReply(
            encryptionParams, keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX), scores.get(1)
        );
        Assert.assertEquals(4L, score0[0]);
        Assert.assertEquals(3L, score1[0]);
    }

    @Test
    public void testNativePackedGroupedCoeffCtCtBloomInnerProductMatch() {
        byte[] encryptionParams = CapePirNativeUtils.generateEncryptionParams(
            POLY_MODULUS_DEGREE, PLAIN_MODULUS, COEFF_MODULUS_BITS
        );
        List<byte[]> keyPair = CapePirNativeUtils.keyGen(encryptionParams);
        long[] queryBits = new long[BLOOM_BIT_LENGTH];
        queryBits[1] = 1L;
        queryBits[3] = 1L;
        queryBits[5] = 1L;
        queryBits[7] = 1L;
        long[] candidatePayload = new long[2 * BLOOM_BIT_LENGTH];
        System.arraycopy(queryBits, 0, candidatePayload, 0, BLOOM_BIT_LENGTH);
        candidatePayload[9] = 1L;
        candidatePayload[BLOOM_BIT_LENGTH + 1] = 1L;
        candidatePayload[BLOOM_BIT_LENGTH + 3] = 1L;
        candidatePayload[BLOOM_BIT_LENGTH + 7] = 1L;
        int blocksPerPackedMatrix = 5;
        int groupNum = (candidatePayload.length + blocksPerPackedMatrix - 1) / blocksPerPackedMatrix;
        List<byte[]> encryptedGroups = new ArrayList<>(groupNum);
        for (int groupIndex = 0; groupIndex < groupNum; groupIndex++) {
            long[] groupPayload = new long[blocksPerPackedMatrix];
            int copyLength = Math.min(blocksPerPackedMatrix, candidatePayload.length - groupIndex * blocksPerPackedMatrix);
            System.arraycopy(candidatePayload, groupIndex * blocksPerPackedMatrix, groupPayload, 0, copyLength);
            encryptedGroups.add(CapePirNativeUtils.encryptCoeffPlain(
                encryptionParams, keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX), groupPayload
            ));
        }
        List<byte[]> encryptedQueryGroups = new ArrayList<>(2 * groupNum);
        for (int valueIndex = 0; valueIndex < 2; valueIndex++) {
            for (int groupIndex = 0; groupIndex < groupNum; groupIndex++) {
                long[] queryPayload = new long[blocksPerPackedMatrix];
                int groupOffset = groupIndex * blocksPerPackedMatrix;
                int valueOffset = valueIndex * BLOOM_BIT_LENGTH;
                for (int blockOffset = 0; blockOffset < blocksPerPackedMatrix; blockOffset++) {
                    int bitIndex = groupOffset + blockOffset - valueOffset;
                    if (bitIndex >= 0 && bitIndex < queryBits.length) {
                        queryPayload[blockOffset] = queryBits[bitIndex];
                    }
                }
                encryptedQueryGroups.add(CapePirNativeUtils.generateEncryptedCoeffBloomFilter(
                    encryptionParams,
                    keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX),
                    keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX),
                    queryPayload
                ));
            }
        }
        List<byte[]> unpackedScores = CapePirNativeUtils.generateCoeffCtCtBloomInnerProductsFromGroupQueries(
            encryptionParams,
            keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX),
            keyPair.get(CapePirNativeUtils.RELIN_KEYS_INDEX),
            encryptedQueryGroups,
            encryptedGroups,
            2
        );
        List<byte[]> packedScores = CapePirNativeUtils.generatePackedCoeffCtCtBloomInnerProductsFromGroupQueries(
            encryptionParams,
            keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX),
            keyPair.get(CapePirNativeUtils.RELIN_KEYS_INDEX),
            keyPair.get(CapePirNativeUtils.GALOIS_KEYS_INDEX),
            encryptedQueryGroups,
            encryptedGroups,
            2
        );
        Assert.assertEquals(2, unpackedScores.size());
        Assert.assertEquals(1, packedScores.size());
        long[] score0 = CapePirNativeUtils.decryptCoeffReply(
            encryptionParams, keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX), unpackedScores.get(0)
        );
        long[] score1 = CapePirNativeUtils.decryptCoeffReply(
            encryptionParams, keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX), unpackedScores.get(1)
        );
        long[] packedScoreCoeffs = CapePirNativeUtils.decryptCoeffReply(
            encryptionParams, keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX), packedScores.get(0)
        );
        Assert.assertEquals(4L, score0[0]);
        Assert.assertEquals(3L, score1[0]);
        Assert.assertEquals(score0[0], normalizePackedScore(packedScoreCoeffs[0]));
        Assert.assertEquals(score1[0], normalizePackedScore(packedScoreCoeffs[1]));
    }

    private static long normalizePackedScore(long packedScore) {
        long inverseScale = inverseMod(POLY_MODULUS_DEGREE % PLAIN_MODULUS, PLAIN_MODULUS);
        return Math.floorMod(packedScore * inverseScale, PLAIN_MODULUS);
    }

    private static long inverseMod(long value, long modulus) {
        long t = 0;
        long newT = 1;
        long r = modulus;
        long newR = Math.floorMod(value, modulus);
        while (newR != 0) {
            long quotient = r / newR;
            long nextT = t - quotient * newT;
            t = newT;
            newT = nextT;
            long nextR = r - quotient * newR;
            r = newR;
            newR = nextR;
        }
        if (r != 1) {
            throw new IllegalStateException("packed score scale is not invertible");
        }
        return Math.floorMod(t, modulus);
    }

    @Test
    public void testNativeBitReplyCoeffCtCtBloomInnerProductMatch() {
        byte[] encryptionParams = CapePirNativeUtils.generateEncryptionParams(
            POLY_MODULUS_DEGREE, PLAIN_MODULUS, COEFF_MODULUS_BITS
        );
        List<byte[]> keyPair = CapePirNativeUtils.keyGen(encryptionParams);
        long[] queryBits = new long[BLOOM_BIT_LENGTH];
        queryBits[1] = 1L;
        queryBits[3] = 1L;
        queryBits[5] = 1L;
        queryBits[7] = 1L;
        List<byte[]> encryptedQueryBits = CapePirNativeUtils.generateEncryptedCoeffBloomScalarBits(
            encryptionParams,
            keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX),
            keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX),
            queryBits
        );
        long[] candidatePayload = new long[2 * BLOOM_BIT_LENGTH];
        System.arraycopy(queryBits, 0, candidatePayload, 0, BLOOM_BIT_LENGTH);
        candidatePayload[9] = 1L;
        candidatePayload[BLOOM_BIT_LENGTH + 1] = 1L;
        candidatePayload[BLOOM_BIT_LENGTH + 3] = 1L;
        candidatePayload[BLOOM_BIT_LENGTH + 7] = 1L;
        List<byte[]> encryptedCandidateBits = new ArrayList<>(candidatePayload.length);
        for (long bit : candidatePayload) {
            encryptedCandidateBits.add(CapePirNativeUtils.encryptCoeffPlain(
                encryptionParams, keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX), new long[]{bit}
            ));
        }
        List<byte[]> scores = CapePirNativeUtils.generateCoeffCtCtBloomInnerProductsFromBitReplies(
            encryptionParams,
            keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX),
            keyPair.get(CapePirNativeUtils.RELIN_KEYS_INDEX),
            encryptedQueryBits,
            encryptedCandidateBits,
            2,
            BLOOM_BIT_LENGTH
        );
        Assert.assertEquals(2, scores.size());
        long[] score0 = CapePirNativeUtils.decryptCoeffReply(
            encryptionParams, keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX), scores.get(0)
        );
        long[] score1 = CapePirNativeUtils.decryptCoeffReply(
            encryptionParams, keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX), scores.get(1)
        );
        Assert.assertEquals(4L, score0[0]);
        Assert.assertEquals(3L, score1[0]);
    }

    @Test
    public void testNativePackedCandidateRetrieval() {
        byte[] encryptionParams = CapePirNativeUtils.generateEncryptionParams(
            CapePirParams.DEFAULT_PARAMS.getPolyModulusDegree(),
            CapePirParams.DEFAULT_PARAMS.getPlainModulus(),
            CapePirParams.DEFAULT_PARAMS.getCoeffModulusBits()
        );
        List<byte[]> keyPair = CapePirNativeUtils.keyGen(encryptionParams);
        int rowNum = 4;
        int colNum = 4;
        int targetRow = 2;
        int targetCol = 1;
        int blocksPerPackedMatrix = 3;
        List<byte[]> columnQueries = new ArrayList<>(3);
        List<byte[]> rowBits = new ArrayList<>(6);
        columnQueries.add(CapePirNativeUtils.generatePackedColumnQuery(
            encryptionParams,
            keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX),
            keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX),
            targetCol,
            colNum,
            blocksPerPackedMatrix
        ));
        rowBits.addAll(CapePirNativeUtils.generateEncryptedRowBits(
            encryptionParams,
            keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX),
            keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX),
            targetRow,
            rowNum
        ));
        for (int i = 0; i < 2; i++) {
            columnQueries.add(CapePirNativeUtils.generatePackedColumnQuery(
                encryptionParams,
                keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX),
                keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX),
                0,
                colNum,
                blocksPerPackedMatrix
            ));
            rowBits.addAll(CapePirNativeUtils.generateEncryptedRowBits(
                encryptionParams,
                keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX),
                keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX),
                0,
                rowNum
            ));
        }
        long[][][] matrices = new long[1][rowNum][colNum * blocksPerPackedMatrix];
        matrices[0][targetRow][targetCol * blocksPerPackedMatrix] = 11L;
        matrices[0][targetRow][targetCol * blocksPerPackedMatrix + 1] = 22L;
        matrices[0][targetRow][targetCol * blocksPerPackedMatrix + 2] = 33L;
        List<byte[]> encodedMatrices = CapePirNativeUtils.preprocessDatabase(
            encryptionParams, matrices, new long[0][]
        );
        List<byte[]> response = CapePirNativeUtils.generateFusePirCandidateReply(
            encryptionParams,
            keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX),
            columnQueries,
            rowBits,
            encodedMatrices,
            blocksPerPackedMatrix,
            rowNum,
            colNum,
            blocksPerPackedMatrix
        );
        Assert.assertEquals(1, response.size());
        long[] coeffs = CapePirNativeUtils.decryptCoeffReply(
            encryptionParams, keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX), response.get(0)
        );
        Assert.assertEquals(11L, coeffs[0]);
        Assert.assertEquals(22L, coeffs[1]);
        Assert.assertEquals(33L, coeffs[2]);
    }

    @Test
    public void testLweToRgswKeyHandleRoundtrip() {
        byte[] encryptionParams = CapePirNativeUtils.generateEncryptionParams(
            CapePirParams.DEFAULT_PARAMS.getPolyModulusDegree(),
            CapePirParams.DEFAULT_PARAMS.getPlainModulus(),
            CapePirParams.DEFAULT_PARAMS.getCoeffModulusBits()
        );
        List<byte[]> keyPair = CapePirNativeUtils.keyGen(encryptionParams);
        long[] lweSecretKey = new long[CapePirNativeUtils.LWE_DIMENSION];
        for (int i = 0; i < lweSecretKey.length; i++) {
            lweSecretKey[i] = (i & 1);
        }
        List<byte[]> lweToRgswKey = CapePirNativeUtils.generateLweToRgswKey(
            encryptionParams, keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX), lweSecretKey
        );
        int rowNum = 4;
        int colNum = 4;
        int targetRow = 2;
        int targetCol = 1;
        int blocksPerPackedMatrix = 3;
        List<byte[]> columnQueries = new ArrayList<>(3);
        columnQueries.add(CapePirNativeUtils.generatePackedColumnQuery(
            encryptionParams,
            keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX),
            keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX),
            targetCol,
            colNum,
            blocksPerPackedMatrix
        ));
        for (int i = 0; i < 2; i++) {
            columnQueries.add(CapePirNativeUtils.generatePackedColumnQuery(
                encryptionParams,
                keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX),
                keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX),
                0,
                colNum,
                blocksPerPackedMatrix
            ));
        }
        long[][][] matrices = new long[1][rowNum][colNum * blocksPerPackedMatrix];
        matrices[0][targetRow][targetCol * blocksPerPackedMatrix] = 11L;
        matrices[0][targetRow][targetCol * blocksPerPackedMatrix + 1] = 22L;
        matrices[0][targetRow][targetCol * blocksPerPackedMatrix + 2] = 33L;
        List<byte[]> encodedMatrices = CapePirNativeUtils.preprocessDatabase(
            encryptionParams, matrices, new long[0][]
        );

        CapeCompressedLweBitQuery targetQuery = CapeLwePrgUtils.generateCompressedRowBitQuery(
            targetRow, rowNum, lweSecretKey, CapePirNativeUtils.LWE_MODULUS, CapePirNativeUtils.DELTA_BIT
        );
        CapeCompressedLweBitQuery zeroQuery = CapeLwePrgUtils.generateCompressedRowBitQuery(
            0, rowNum, lweSecretKey, CapePirNativeUtils.LWE_MODULUS, CapePirNativeUtils.DELTA_BIT
        );
        List<CapeLweCiphertext> recoveredBits = new ArrayList<>();
        recoveredBits.addAll(CapeLwePrgUtils.recoverLweBitCiphertexts(targetQuery));
        recoveredBits.addAll(CapeLwePrgUtils.recoverLweBitCiphertexts(zeroQuery));
        recoveredBits.addAll(CapeLwePrgUtils.recoverLweBitCiphertexts(zeroQuery));
        long[][] aArray = new long[recoveredBits.size()][];
        long[] bArray = new long[recoveredBits.size()];
        for (int i = 0; i < recoveredBits.size(); i++) {
            aArray[i] = recoveredBits.get(i).getA();
            bArray[i] = recoveredBits.get(i).getB();
        }

        List<byte[]> oldRowBits = CapePirNativeUtils.convertCompressedRowBitsToRgsw(
            encryptionParams, keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX), lweToRgswKey, aArray, bArray
        );
        long handle = CapePirNativeUtils.createLweToRgswKeyHandle(
            encryptionParams, keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX), lweToRgswKey
        );
        Assert.assertTrue(handle != 0L);
        try {
            List<byte[]> handleRowBits = CapePirNativeUtils.convertCompressedRowBitsToRgswWithHandle(
                encryptionParams, keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX), handle, aArray, bArray
            );
            long[] oldCoeffs = decryptCandidateReply(
                encryptionParams, keyPair, columnQueries, oldRowBits, encodedMatrices, blocksPerPackedMatrix, rowNum,
                colNum
            );
            long[] handleCoeffs = decryptCandidateReply(
                encryptionParams, keyPair, columnQueries, handleRowBits, encodedMatrices, blocksPerPackedMatrix, rowNum,
                colNum
            );
            Assert.assertEquals(oldCoeffs[0], handleCoeffs[0]);
            Assert.assertEquals(oldCoeffs[1], handleCoeffs[1]);
            Assert.assertEquals(oldCoeffs[2], handleCoeffs[2]);
            Assert.assertEquals(11L, handleCoeffs[0]);
            Assert.assertEquals(22L, handleCoeffs[1]);
            Assert.assertEquals(33L, handleCoeffs[2]);
        } finally {
            CapePirNativeUtils.destroyLweToRgswKeyHandle(handle);
        }
        try {
            CapePirNativeUtils.convertCompressedRowBitsToRgswWithHandle(
                encryptionParams, keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX), handle, aArray, bArray
            );
            Assert.fail("destroyed LWE-to-RGSW key handle should fail closed");
        } catch (RuntimeException expected) {
            // expected
        }
    }

    @Test
    public void testNativeSplitCandidateItem() {
        byte[] encryptionParams = CapePirNativeUtils.generateEncryptionParams(
            POLY_MODULUS_DEGREE, PLAIN_MODULUS, COEFF_MODULUS_BITS
        );
        List<byte[]> keyPair = CapePirNativeUtils.keyGen(encryptionParams);
        int fingerprintByteLength = 2;
        int valueByteLength = 2;
        int bloomByteLength = 4;
        int payloadItemByteLength = 1 + valueByteLength + bloomByteLength;
        long[] slots = new long[POLY_MODULUS_DEGREE];
        slots[fingerprintByteLength] = 1L;
        slots[fingerprintByteLength + 1] = 11L;
        slots[fingerprintByteLength + 2] = 22L;
        slots[fingerprintByteLength + 3] = 1L;
        slots[fingerprintByteLength + 4] = 0L;
        slots[fingerprintByteLength + 5] = 1L;
        slots[fingerprintByteLength + 6] = 1L;
        byte[] encryptedPayload = CapePirNativeUtils.generateEncryptedBloomFilter(
            encryptionParams,
            keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX),
            keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX),
            slots
        ).get(0);
        List<byte[]> split = CapePirNativeUtils.splitCandidateItemCiphertext(
            encryptionParams, encryptedPayload, 0, fingerprintByteLength, valueByteLength, bloomByteLength,
            payloadItemByteLength
        );
        Assert.assertEquals(2, split.size());
        long[] valueCoeffs = CapePirNativeUtils.decryptReply(
            encryptionParams, keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX), split.get(0)
        );
        Assert.assertEquals(0L, valueCoeffs[fingerprintByteLength]);
        Assert.assertEquals(11L, valueCoeffs[fingerprintByteLength + 1]);
        Assert.assertEquals(22L, valueCoeffs[fingerprintByteLength + 2]);
        Assert.assertEquals(0L, valueCoeffs[fingerprintByteLength + 3]);
        long[] bloomCoeffs = CapePirNativeUtils.decryptReply(
            encryptionParams, keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX), split.get(1)
        );
        Assert.assertEquals(0L, bloomCoeffs[fingerprintByteLength + 1]);
        Assert.assertEquals(0L, bloomCoeffs[fingerprintByteLength + 2]);
        Assert.assertEquals(1L, bloomCoeffs[fingerprintByteLength + 3]);
        Assert.assertEquals(0L, bloomCoeffs[fingerprintByteLength + 4]);
        Assert.assertEquals(1L, bloomCoeffs[fingerprintByteLength + 5]);
        Assert.assertEquals(1L, bloomCoeffs[fingerprintByteLength + 6]);
    }

    private long computeBloomInnerProduct(long[] queryBits, long[] valueBits) {
        byte[] encryptionParams = CapePirNativeUtils.generateEncryptionParams(
            POLY_MODULUS_DEGREE, PLAIN_MODULUS, COEFF_MODULUS_BITS
        );
        List<byte[]> keyPair = CapePirNativeUtils.keyGen(encryptionParams);
        Assert.assertEquals(4, keyPair.size());
        List<byte[]> encryptedBloomFilter = CapePirNativeUtils.generateEncryptedBloomFilter(
            encryptionParams,
            keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX),
            keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX),
            queryBits
        );
        Assert.assertEquals(1, encryptedBloomFilter.size());
        long[][] valueBloomFilters = new long[][]{valueBits};
        List<byte[]> encodedValueBloomFilters = CapePirNativeUtils.preprocessDatabase(
            encryptionParams, new long[0][][], valueBloomFilters
        );
        Assert.assertEquals(1, encodedValueBloomFilters.size());
        List<byte[]> scores = CapePirNativeUtils.generateBloomInnerProductsForTest(
            encryptionParams,
            keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX),
            keyPair.get(CapePirNativeUtils.GALOIS_KEYS_INDEX),
            encryptedBloomFilter,
            encodedValueBloomFilters
        );
        Assert.assertEquals(1, scores.size());
        long[] decrypted = CapePirNativeUtils.decryptReply(
            encryptionParams, keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX), scores.get(0)
        );
        return decrypted[0];
    }

    private long computeCtCtBloomInnerProduct(long[] queryBits, long[] valueBits) {
        byte[] encryptionParams = CapePirNativeUtils.generateEncryptionParams(
            POLY_MODULUS_DEGREE, PLAIN_MODULUS, COEFF_MODULUS_BITS
        );
        List<byte[]> keyPair = CapePirNativeUtils.keyGen(encryptionParams);
        Assert.assertEquals(4, keyPair.size());
        List<byte[]> encryptedQueryBloomFilter = CapePirNativeUtils.generateEncryptedBloomFilter(
            encryptionParams,
            keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX),
            keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX),
            queryBits
        );
        List<byte[]> encryptedCandidateBloomFilters = new ArrayList<>(CapePirNativeUtils.generateEncryptedBloomFilter(
            encryptionParams,
            keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX),
            keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX),
            valueBits
        ));
        List<byte[]> scores = CapePirNativeUtils.generateCtCtBloomInnerProducts(
            encryptionParams,
            keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX),
            keyPair.get(CapePirNativeUtils.RELIN_KEYS_INDEX),
            keyPair.get(CapePirNativeUtils.GALOIS_KEYS_INDEX),
            encryptedQueryBloomFilter,
            encryptedCandidateBloomFilters
        );
        Assert.assertEquals(1, scores.size());
        long[] decrypted = CapePirNativeUtils.decryptReply(
            encryptionParams, keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX), scores.get(0)
        );
        return decrypted[0];
    }

    private static long[] decryptCandidateReply(byte[] encryptionParams, List<byte[]> keyPair,
                                                List<byte[]> columnQueries, List<byte[]> rowBits,
                                                List<byte[]> encodedMatrices, int blocksPerPackedMatrix,
                                                int rowNum, int colNum) {
        List<byte[]> response = CapePirNativeUtils.generateFusePirCandidateReply(
            encryptionParams,
            keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX),
            columnQueries,
            rowBits,
            encodedMatrices,
            blocksPerPackedMatrix,
            rowNum,
            colNum,
            blocksPerPackedMatrix
        );
        Assert.assertEquals(1, response.size());
        return CapePirNativeUtils.decryptCoeffReply(
            encryptionParams, keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX), response.get(0)
        );
    }
}
