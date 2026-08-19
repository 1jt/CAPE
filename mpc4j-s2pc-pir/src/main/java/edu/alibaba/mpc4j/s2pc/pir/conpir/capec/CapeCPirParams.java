package edu.alibaba.mpc4j.s2pc.pir.conpir.capec;

import edu.alibaba.mpc4j.common.tool.CommonConstants;
import edu.alibaba.mpc4j.common.tool.MathPreconditions;
import edu.alibaba.mpc4j.common.tool.utils.BytesUtils;
import edu.alibaba.mpc4j.s2pc.pir.conpir.cape.CapePirParams;
import edu.alibaba.mpc4j.s2pc.pir.conpir.cape.CapePirQueryMethod;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * CAPE_C PIR params.
 *
 * <p>Phase 1 keeps CAPE_C aligned with CAPE's BFV score / packed-result parameter surface. Only the anchor query
 * representation is changed from CAPE's column-query plus compressed-row-bit query shape to one compressed
 * row+column-bit anchor query.</p>
 *
 * @author Weiran Liu
 * @date 2026/07/07
 */
public class CapeCPirParams extends CapePirParams {
    /**
     * default params, aligned to CAPE.
     */
    public static final CapeCPirParams DEFAULT_PARAMS = new CapeCPirParams(
        16384, 65537L, new int[0], 3, 40, 16, 3, true,
        Math.pow(2.0, -CapePirParams.BLOOM_FALSE_POSITIVE_EXPONENT),
        new byte[CommonConstants.BLOCK_BYTE_LENGTH], CapePirQueryMethod.AND, 3
    );

    public CapeCPirParams(int polyModulusDegree, long plainModulus, int[] coeffModulusBits, int bffHashNum,
                         int fingerprintBitLength, int valueByteLength, int maxValueNumPerKeyword,
                         boolean enablePayloadSplit, double bloomFalsePositiveProbability, byte[] bloomSeed,
                         CapePirQueryMethod queryMethod, int boolKeywordNum) {
        super(polyModulusDegree, plainModulus, coeffModulusBits, bffHashNum, fingerprintBitLength, valueByteLength,
            maxValueNumPerKeyword, enablePayloadSplit, bloomFalsePositiveProbability, bloomSeed, queryMethod,
            boolKeywordNum);
    }

    public CapeCPirParams(CapePirParams params) {
        super(params);
    }

    /**
     * Keyword number from the latest CAPE_C parameter initialization.
     */
    private int keywordNum;

    @Override
    public void initPirParams(int keywordNum, int valueByteLength, int maxValueNumPerKeyword, int boolKeywordNum) {
        this.keywordNum = keywordNum;
        super.initPirParams(keywordNum, valueByteLength, maxValueNumPerKeyword, boolKeywordNum);
    }

    @Override
    public void initPirParams(int keywordNum, int valueByteLength, int maxValueNumPerKeyword, int boolKeywordNum,
                              int valueBloomExpectedInsertions) {
        this.keywordNum = keywordNum;
        super.initPirParams(keywordNum, valueByteLength, maxValueNumPerKeyword, boolKeywordNum,
            valueBloomExpectedInsertions);
    }

    byte[] serializeCapeCBloomParams() {
        byte[] bloomSeed = getBloomSeed();
        return ByteBuffer.allocate(Integer.BYTES * 5 + bloomSeed.length)
            .putInt(getBloomExpectedInsertions())
            .putInt(getBloomBitLength())
            .putInt(getBloomHashNum())
            .putInt(getBlocksPerPackedMatrix())
            .putInt(bloomSeed.length)
            .put(bloomSeed)
            .array();
    }

    void applySerializedCapeCBloomParams(byte[] serializedBloomParams) {
        ByteBuffer buffer = ByteBuffer.wrap(BytesUtils.clone(serializedBloomParams));
        int expectedInsertions = buffer.getInt();
        int bitLength = buffer.getInt();
        int hashNum = buffer.getInt();
        int blocksPerPackedMatrix = buffer.getInt();
        int seedLength = buffer.getInt();
        MathPreconditions.checkPositive("serialized_bloom_expected_insertions", expectedInsertions);
        MathPreconditions.checkPositive("serialized_bloom_bit_length", bitLength);
        MathPreconditions.checkPositive("serialized_bloom_hash_num", hashNum);
        MathPreconditions.checkPositive("serialized_blocks_per_packed_matrix", blocksPerPackedMatrix);
        MathPreconditions.checkEqual(
            "bloom_seed.length", "CommonConstants.BLOCK_BYTE_LENGTH", seedLength, CommonConstants.BLOCK_BYTE_LENGTH
        );
        byte[] seed = new byte[seedLength];
        buffer.get(seed);
        MathPreconditions.checkEqual("serialized_bloom_params.remaining", "0", buffer.remaining(), 0);
        MathPreconditions.checkEqual("serialized_bloom_hash_num", "local_bloom_hash_num", hashNum, getBloomHashNum());
        MathPreconditions.checkEqual(
            "serialized_bloom_seed", "local_bloom_seed", Arrays.equals(seed, getBloomSeed()) ? 1 : 0, 1
        );
        initPirParams(
            keywordNum, getValueByteLength(), getMaxValueNumPerKeyword(), getBoolKeywordNum(), expectedInsertions
        );
        recomputeMatrixAndPackingWithSerializedPreference(blocksPerPackedMatrix);
        MathPreconditions.checkEqual("serialized_bloom_bit_length", "local_bloom_bit_length", bitLength,
            getBloomBitLength());
        MathPreconditions.checkEqual(
            "serialized_blocks_per_packed_matrix", "local_blocks_per_packed_matrix", blocksPerPackedMatrix,
            getBlocksPerPackedMatrix()
        );
    }

    private void recomputeMatrixAndPackingWithSerializedPreference(int blocksPerPackedMatrix) {
        try {
            java.lang.reflect.Method method = CapePirParams.class.getDeclaredMethod(
                "recomputeMatrixAndPacking", int.class
            );
            method.setAccessible(true);
            method.invoke(this, blocksPerPackedMatrix);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Cannot apply CAPE_C serialized Bloom packing parameters", e);
        }
    }
}
