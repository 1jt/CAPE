package edu.alibaba.mpc4j.s2pc.pir.conpir.cape;

import edu.alibaba.mpc4j.common.structure.fusefilter.Arity3ByteFusePosition;
import edu.alibaba.mpc4j.common.tool.CommonConstants;
import edu.alibaba.mpc4j.common.tool.EnvType;
import edu.alibaba.mpc4j.common.tool.MathPreconditions;
import edu.alibaba.mpc4j.common.tool.utils.CommonUtils;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * CAPE PIR params.
 *
 * <p>CAPE reuses FUSE_PIR's additive Binary Fuse Filter / matrix retrieval layout for the anchor keyword. It additionally
 * attaches a Bloom Filter to every candidate value and evaluates encrypted Bloom inner products for the non-anchor
 * keywords. The Bloom Filter is CAPE-local so the experimental false-positive exponent can be controlled without
 * changing shared filter defaults.</p>
 *
 * @author Weiran Liu
 * @date 2026/06/06
 */
public class CapePirParams {
    /**
     * Experimental CAPE value Bloom Filter false-positive exponent.
     */
    public static final int BLOOM_FALSE_POSITIVE_EXPONENT = 10;
    /**
     * default params.
     *
     * <p>The SEAL/BFV layer uses SEAL's default tc128 coefficient modulus. Non-SEAL LWE/RGSW material is unchanged
     * and requires separate security assessment.</p>
     */
    public static final CapePirParams DEFAULT_PARAMS = new CapePirParams(
        16384, 65537L, new int[0], 3, 40, 16, 3, true,
        Math.pow(2.0, -BLOOM_FALSE_POSITIVE_EXPONENT), new byte[CommonConstants.BLOCK_BYTE_LENGTH],
        CapePirQueryMethod.AND, 3
    );
    /**
     * poly modulus degree.
     */
    private final int polyModulusDegree;
    /**
     * plain modulus.
     */
    private final long plainModulus;
    /**
     * Deprecated JNI compatibility placeholder. Formal native code ignores this and uses SEAL BFVDefault(tc128).
     */
    private final int[] coeffModulusBits;
    /**
     * BFF hash num.
     */
    private final int bffHashNum;
    /**
     * fingerprint bit length.
     */
    private final int fingerprintBitLength;
    /**
     * value byte length.
     */
    private int valueByteLength;
    /**
     * max value num per keyword.
     */
    private int maxValueNumPerKeyword;
    /**
     * enable payload split.
     */
    private final boolean enablePayloadSplit;
    /**
     * payload element bit length.
     */
    private final int payloadElementBitLength;
    /**
     * Bloom Filter false positive probability requested by the CAPE config.
     */
    private final double bloomFalsePositiveProbability;
    /**
     * Bloom Filter seed.
     */
    private byte[] bloomSeed;
    /**
     * query method.
     */
    private CapePirQueryMethod queryMethod;
    /**
     * boolean keyword num.
     */
    private int boolKeywordNum;
    /**
     * BFF slot num.
     */
    private int bffSlotNum;
    /**
     * matrix row num.
     */
    private int matrixRowNum;
    /**
     * matrix column num.
     */
    private int matrixColNum;
    /**
     * payload block num.
     */
    private int payloadBlockNum;
    /**
     * blocks per packed matrix.
     */
    private int blocksPerPackedMatrix;
    /**
     * packed matrix group num.
     */
    private int packedMatrixGroupNum;
    /**
     * Bloom Filter bit length.
     */
    private int bloomBitLength;
    /**
     * Bloom Filter hash num.
     */
    private int bloomHashNum;
    /**
     * Bloom Filter expected insertions.
     */
    private int bloomExpectedInsertions;
    /**
     * encryption params.
     */
    public byte[] encryptionParams;

    public CapePirParams(int polyModulusDegree, long plainModulus, int[] coeffModulusBits, int bffHashNum,
                        int fingerprintBitLength, int valueByteLength, int maxValueNumPerKeyword,
                        boolean enablePayloadSplit, double bloomFalsePositiveProbability, byte[] bloomSeed,
                        CapePirQueryMethod queryMethod, int boolKeywordNum) {
        MathPreconditions.checkPositive("poly_modulus_degree", polyModulusDegree);
        MathPreconditions.checkGreater("plain_modulus", plainModulus, 1L);
        MathPreconditions.checkEqual("bff_hash_num", "3", bffHashNum, 3);
        MathPreconditions.checkPositive("fingerprint_bit_length", fingerprintBitLength);
        MathPreconditions.checkPositive("value_byte_length", valueByteLength);
        MathPreconditions.checkPositive("max_value_num_per_keyword", maxValueNumPerKeyword);
        MathPreconditions.checkGreater("bloom_false_positive_probability", bloomFalsePositiveProbability, 0.0);
        MathPreconditions.checkLessOrEqual("bloom_false_positive_probability", bloomFalsePositiveProbability, 1.0);
        MathPreconditions.checkEqual(
            "bloom_seed.length", "CommonConstants.BLOCK_BYTE_LENGTH", bloomSeed.length,
            CommonConstants.BLOCK_BYTE_LENGTH
        );
        MathPreconditions.checkGreaterOrEqual("bool_keyword_num", boolKeywordNum, 2);
        this.polyModulusDegree = polyModulusDegree;
        this.plainModulus = plainModulus;
        this.coeffModulusBits = Arrays.copyOf(coeffModulusBits, coeffModulusBits.length);
        this.bffHashNum = bffHashNum;
        this.fingerprintBitLength = fingerprintBitLength;
        this.valueByteLength = valueByteLength;
        this.maxValueNumPerKeyword = maxValueNumPerKeyword;
        this.enablePayloadSplit = enablePayloadSplit;
        this.bloomFalsePositiveProbability = bloomFalsePositiveProbability;
        this.bloomSeed = Arrays.copyOf(bloomSeed, bloomSeed.length);
        this.queryMethod = queryMethod;
        this.boolKeywordNum = boolKeywordNum;
        // Keep value-only payload shares byte-wise. A 16-bit value-only block changes the packed CAPE candidate
        // retrieval layout and fails correctness under the current compressed-row native path. Bloom-only score
        // payloads still use one bit per coefficient.
        payloadElementBitLength = Byte.SIZE;
    }

    public CapePirParams(CapePirParams params) {
        this(params.polyModulusDegree, params.plainModulus, params.coeffModulusBits, params.bffHashNum,
            params.fingerprintBitLength, params.valueByteLength, params.maxValueNumPerKeyword,
            params.enablePayloadSplit, params.bloomFalsePositiveProbability, params.bloomSeed,
            params.queryMethod, params.boolKeywordNum);
        bffSlotNum = params.bffSlotNum;
        matrixRowNum = params.matrixRowNum;
        matrixColNum = params.matrixColNum;
        payloadBlockNum = params.payloadBlockNum;
        blocksPerPackedMatrix = params.blocksPerPackedMatrix;
        packedMatrixGroupNum = params.packedMatrixGroupNum;
        bloomBitLength = params.bloomBitLength;
        bloomHashNum = params.bloomHashNum;
        bloomExpectedInsertions = params.bloomExpectedInsertions;
        encryptionParams = params.encryptionParams == null ? null : Arrays.copyOf(params.encryptionParams,
            params.encryptionParams.length);
    }

    public void initPirParams(int keywordNum, int valueByteLength, int maxValueNumPerKeyword, int boolKeywordNum) {
        initPirParams(keywordNum, valueByteLength, maxValueNumPerKeyword, boolKeywordNum, keywordNum);
    }

    public void initPirParams(int keywordNum, int valueByteLength, int maxValueNumPerKeyword, int boolKeywordNum,
                              int valueBloomExpectedInsertions) {
        MathPreconditions.checkPositive("keyword_num", keywordNum);
        MathPreconditions.checkPositive("value_byte_length", valueByteLength);
        MathPreconditions.checkPositive("max_value_num_per_keyword", maxValueNumPerKeyword);
        MathPreconditions.checkGreaterOrEqual("bool_keyword_num", boolKeywordNum, 2);
        MathPreconditions.checkPositive("value_bloom_expected_insertions", valueBloomExpectedInsertions);
        this.valueByteLength = valueByteLength;
        this.maxValueNumPerKeyword = maxValueNumPerKeyword;
        this.boolKeywordNum = boolKeywordNum;
        Arity3ByteFusePosition<byte[]> fusePosition = new Arity3ByteFusePosition<>(
            EnvType.STANDARD, keywordNum, getPayloadBlockByteLength(), new byte[CommonConstants.BLOCK_BYTE_LENGTH]
        );
        bffSlotNum = fusePosition.filterLength();
        payloadBlockNum = CommonUtils.getUnitNum(getPayloadByteLength(), getPayloadBlockByteLength());
        if (!enablePayloadSplit) {
            MathPreconditions.checkEqual("payload_block_num", "1", payloadBlockNum, 1);
        }
        setBloomParams(valueBloomExpectedInsertions, bloomBitSize(valueBloomExpectedInsertions),
            BLOOM_FALSE_POSITIVE_EXPONENT, bloomSeed);
        recomputeMatrixAndPacking(payloadBlockNum);
        // Encryption parameters depend only on the BFV parameter tuple, not on database dimensions. The server can
        // receive setup keys before formal init and pre-create this blob for native handle construction, so keep it.
    }

    void setBloomParams(int bloomExpectedInsertions, int bloomBitLength, int bloomHashNum, byte[] bloomSeed) {
        MathPreconditions.checkPositive("bloom_expected_insertions", bloomExpectedInsertions);
        MathPreconditions.checkPositive("bloom_bit_length", bloomBitLength);
        MathPreconditions.checkPositive("bloom_hash_num", bloomHashNum);
        MathPreconditions.checkEqual(
            "bloom_seed.length", "CommonConstants.BLOCK_BYTE_LENGTH", bloomSeed.length,
            CommonConstants.BLOCK_BYTE_LENGTH
        );
        this.bloomExpectedInsertions = bloomExpectedInsertions;
        this.bloomBitLength = bloomBitLength;
        this.bloomHashNum = bloomHashNum;
        this.bloomSeed = Arrays.copyOf(bloomSeed, bloomSeed.length);
    }

    byte[] serializeBloomParams() {
        ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES * 5 + bloomSeed.length);
        buffer.putInt(bloomExpectedInsertions);
        buffer.putInt(bloomBitLength);
        buffer.putInt(bloomHashNum);
        buffer.putInt(blocksPerPackedMatrix);
        buffer.putInt(bloomSeed.length);
        buffer.put(bloomSeed);
        return buffer.array();
    }

    void applySerializedBloomParams(byte[] serializedBloomParams) {
        ByteBuffer buffer = ByteBuffer.wrap(serializedBloomParams);
        int expectedInsertions = buffer.getInt();
        int bitLength = buffer.getInt();
        int hashNum = buffer.getInt();
        int serializedBlocksPerPackedMatrix = buffer.getInt();
        int seedLength = buffer.getInt();
        MathPreconditions.checkPositive("serialized_blocks_per_packed_matrix", serializedBlocksPerPackedMatrix);
        MathPreconditions.checkEqual(
            "bloom_seed.length", "CommonConstants.BLOCK_BYTE_LENGTH", seedLength, CommonConstants.BLOCK_BYTE_LENGTH
        );
        byte[] seed = new byte[seedLength];
        buffer.get(seed);
        MathPreconditions.checkEqual("serialized_bloom_params.remaining", "0", buffer.remaining(), 0);
        setBloomParams(expectedInsertions, bitLength, hashNum, seed);
        recomputeMatrixAndPacking(serializedBlocksPerPackedMatrix);
    }

    private void recomputeMatrixAndPacking(int preferredBlocksPerPackedMatrix) {
        /*
         * P10's packed Bloom payload uses coefficientStride as the row-selection stride. The raw row width is split
         * into column tiles later, so only rowNum * coefficientStride must fit in one BFV plaintext here.
         */
        int maxPackedBloomRows = polyModulusDegree / bloomBitLength;
        MathPreconditions.checkPositive("max_packed_bloom_rows", maxPackedBloomRows);
        matrixRowNum = bffSlotNum <= maxPackedBloomRows
            ? bffSlotNum
            : maxPackedBloomRows;
        matrixColNum = CommonUtils.getUnitNum(bffSlotNum, matrixRowNum);
        int maxColumnQueryStride = polyModulusDegree / Math.max(1, matrixRowNum * matrixColNum);
        blocksPerPackedMatrix = Math.min(preferredBlocksPerPackedMatrix, maxColumnQueryStride);
        MathPreconditions.checkPositive("blocks_per_packed_matrix", blocksPerPackedMatrix);
        packedMatrixGroupNum = CommonUtils.getUnitNum(payloadBlockNum, blocksPerPackedMatrix);
    }

    boolean alignedToFusePirParams() {
        return polyModulusDegree == 16384 && plainModulus == 65537L && coeffModulusBits.length == 0;
    }

    public int getPolyModulusDegree() {
        return polyModulusDegree;
    }

    public long getPlainModulus() {
        return plainModulus;
    }

    public int[] getCoeffModulusBits() {
        return Arrays.copyOf(coeffModulusBits, coeffModulusBits.length);
    }

    public int getBffHashNum() {
        return bffHashNum;
    }

    public int getBffSlotNum() {
        return bffSlotNum;
    }

    public int getMatrixRowNum() {
        return matrixRowNum;
    }

    public int getMatrixColNum() {
        return matrixColNum;
    }

    public int getFingerprintBitLength() {
        return fingerprintBitLength;
    }

    public int getFingerprintByteLength() {
        return CommonUtils.getByteLength(fingerprintBitLength);
    }

    public int getValueByteLength() {
        return valueByteLength;
    }

    public int getMaxValueNumPerKeyword() {
        return maxValueNumPerKeyword;
    }

    public int getPayloadBlockNum() {
        return payloadBlockNum;
    }

    public int getBlocksPerPackedMatrix() {
        return blocksPerPackedMatrix;
    }

    public int getValueBlocksPerPackedMatrix() {
        return blocksPerPackedMatrix;
    }

    public int getPackedMatrixGroupNum() {
        return packedMatrixGroupNum;
    }

    public boolean isEnablePayloadSplit() {
        return enablePayloadSplit;
    }

    public int getPayloadByteLength() {
        return getFingerprintByteLength() + maxValueNumPerKeyword * getPayloadItemByteLength();
    }

    public int getPayloadItemByteLength() {
        return Byte.BYTES + valueByteLength + getBloomByteLength();
    }

    public int getPayloadBlockByteLength() {
        return CommonUtils.getByteLength(payloadElementBitLength);
    }

    public int getPayloadElementBitLength() {
        return payloadElementBitLength;
    }

    public int getValueEncodingChunkBitLength() {
        return 16;
    }

    public long getAbsentValueSentinel() {
        return plainModulus - 1;
    }

    public int getFingerprintCoeffNum() {
        return CommonUtils.getUnitNum(fingerprintBitLength, getValueEncodingChunkBitLength());
    }

    public int getValueCoeffNum() {
        return CommonUtils.getUnitNum(valueByteLength * Byte.SIZE, getValueEncodingChunkBitLength());
    }

    public int getValuePayloadCoeffNum() {
        return getFingerprintCoeffNum() + maxValueNumPerKeyword * getValueCoeffNum();
    }

    public int getScoreCoeffNum() {
        return maxValueNumPerKeyword;
    }

    public int getScoreOffset() {
        int valuePayloadCoeffNum = getValuePayloadCoeffNum();
        int scoreCoeffNum = getScoreCoeffNum();
        int localOffset = valuePayloadCoeffNum % polyModulusDegree;
        if (localOffset == 0 || localOffset + scoreCoeffNum <= polyModulusDegree) {
            return valuePayloadCoeffNum;
        }
        return CommonUtils.getUnitNum(valuePayloadCoeffNum, polyModulusDegree) * polyModulusDegree;
    }

    public int getTotalResultCoeffNum() {
        return getScoreOffset() + getScoreCoeffNum();
    }

    public int getExpectedPackedResultCiphertextCount() {
        return CommonUtils.getUnitNum(getTotalResultCoeffNum(), polyModulusDegree);
    }

    public boolean supportOneCoeffValueEncoding() {
        return plainModulus == 65537L && valueByteLength <= Short.BYTES;
    }

    public int getBloomBitLength() {
        return bloomBitLength;
    }

    public int getBloomByteLength() {
        return CommonUtils.getByteLength(bloomBitLength);
    }

    public int getBloomHashNum() {
        return bloomHashNum;
    }

    public int getBloomCiphertextNum() {
        return CommonUtils.getUnitNum(bloomBitLength, polyModulusDegree);
    }

    public int getCoeffBloomCiphertextNum() {
        return getPackedQueryBloomCiphertextNum();
    }

    public int getPackedQueryBloomCiphertextNum() {
        return CommonUtils.getUnitNum(bloomBitLength, polyModulusDegree);
    }

    public int getBloomPerPackedBlock() {
        if (bloomBitLength <= 0 || bloomBitLength > polyModulusDegree) {
            throw new IllegalArgumentException("bloomBitLength must be in (0, polyModulusDegree]");
        }
        /*
         * Native row selection uses the packed Bloom coefficient stride between matrix rows. Matrix columns are
         * streamed in tiles, so candidates per packed block are limited by row stride only.
         */
        int maxCoefficientStride = polyModulusDegree / Math.max(1, matrixRowNum);
        return Math.max(1, maxCoefficientStride / bloomBitLength);
    }

    public int getBloomPackedPayloadBlockNum() {
        return CommonUtils.getUnitNum(maxValueNumPerKeyword, getBloomPerPackedBlock());
    }

    int getBloomPackedCoefficientStride() {
        return getBloomPerPackedBlock() * bloomBitLength;
    }

    int getBloomPackedMatrixColumnCapacity() {
        int coefficientStride = getBloomPackedCoefficientStride();
        MathPreconditions.checkPositive("bloom_packed_coefficient_stride", coefficientStride);
        int columnCapacity = polyModulusDegree / coefficientStride;
        MathPreconditions.checkPositive("bloom_packed_matrix_column_capacity", columnCapacity);
        return columnCapacity;
    }

    int getBloomPackedMatrixColumnTileNum() {
        return CommonUtils.getUnitNum(matrixColNum, getBloomPackedMatrixColumnCapacity());
    }

    /**
     * Previous scalar Bloom payload block count. Kept only for test-only accounting and legacy helpers.
     */
    @Deprecated
    public int getScalarBloomPayloadBlockNumForTest() {
        return maxValueNumPerKeyword * bloomBitLength;
    }

    /**
     * Previous packed Bloom query count tied to the bloom-only scalar payload group size. Kept for test-only
     * reference and logging.
     */
    @Deprecated
    public int getPackedBloomQueryCiphertextNum() {
        return CommonUtils.getUnitNum(bloomBitLength, blocksPerPackedMatrix);
    }

    /**
     * Previous P9 global/tiled query count. Kept only for test-only consistency checks.
     */
    @Deprecated
    public int getGlobalTiledCoeffBloomCiphertextNum() {
        return CommonUtils.getUnitNum(maxValueNumPerKeyword * bloomBitLength, blocksPerPackedMatrix);
    }

    /**
     * Previous P7 per-value compact query count. Kept only for test-only consistency checks.
     */
    @Deprecated
    public int getCompactCoeffBloomCiphertextNum() {
        return maxValueNumPerKeyword * CommonUtils.getUnitNum(
            maxValueNumPerKeyword * bloomBitLength, blocksPerPackedMatrix
        );
    }

    public int getBloomExpectedInsertions() {
        return bloomExpectedInsertions;
    }

    public double getBloomFalsePositiveProbability() {
        return bloomFalsePositiveProbability;
    }

    public int getBloomFalsePositiveExponent() {
        return BLOOM_FALSE_POSITIVE_EXPONENT;
    }

    public byte[] getBloomSeed() {
        return Arrays.copyOf(bloomSeed, bloomSeed.length);
    }

    public CapePirQueryMethod getQueryMethod() {
        return queryMethod;
    }

    private static int largestDivisorAtMost(int value, int upperBound) {
        for (int divisor = Math.min(value, upperBound); divisor >= 1; divisor--) {
            if (value % divisor == 0) {
                return divisor;
            }
        }
        return 1;
    }

    public int getBoolKeywordNum() {
        return boolKeywordNum;
    }

    static int bloomBitSize(int expectedInsertions) {
        return bloomBitSize(expectedInsertions, BLOOM_FALSE_POSITIVE_EXPONENT);
    }

    static int bloomBitSize(int expectedInsertions, int falsePositiveExponent) {
        MathPreconditions.checkPositive("expected_insertions", expectedInsertions);
        MathPreconditions.checkPositive("false_positive_exponent", falsePositiveExponent);
        int bitLength = (int) Math.ceil(expectedInsertions * falsePositiveExponent / Math.log(2));
        return CommonUtils.getByteLength(bitLength) * Byte.SIZE;
    }
}
