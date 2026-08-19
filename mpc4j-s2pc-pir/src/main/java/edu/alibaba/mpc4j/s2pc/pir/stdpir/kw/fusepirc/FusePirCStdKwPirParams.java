package edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepirc;

import edu.alibaba.mpc4j.common.structure.fusefilter.Arity3ByteFusePosition;
import edu.alibaba.mpc4j.common.tool.EnvType;
import edu.alibaba.mpc4j.common.tool.MathPreconditions;
import edu.alibaba.mpc4j.common.tool.utils.CommonUtils;
import edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.StdKwPirParams;

import java.util.Arrays;

/**
 * FUSE_PIR_C standard keyword PIR params.
 *
 * @author Weiran Liu
 * @date 2026/06/16
 */
public class FusePirCStdKwPirParams implements StdKwPirParams {
    /**
     * Legacy payload blocks packed per response ciphertext, kept only for layout comparison logs.
     */
    private static final int LEGACY_BLOCKS_PER_PACKED_MATRIX = 128;
    /**
     * Target amortized response bytes per 16-bit payload block.
     */
    private static final int TARGET_RESPONSE_BYTES_PER_PAYLOAD_BLOCK = 100;
    /**
     * FUSE_PIR_C parameter sets.
     */
    enum ParameterSet {
        /**
         * Correctness-only small parameter set.
         */
        RAW_CORRECTNESS,
        /**
         * Paper-aligned 128-bit candidate. Estimator validation is pending.
         */
        CMUX_128_CANDIDATE,
        /**
         * Layout fairness candidate. Estimator validation is pending.
         */
        LAYOUT_16384_CANDIDATE,
    }
    /**
     * RAW correctness params.
     */
    static final FusePirCStdKwPirParams RAW_CORRECTNESS_PARAMS = new FusePirCStdKwPirParams(
        ParameterSet.RAW_CORRECTNESS, 16, 65537L, new int[]{36}, 3, 40, 16, 3, true,
        FusePirCLweParams.RAW_CORRECTNESS, FusePirCCircuitBootstrapParams.RAW_CORRECTNESS
    );
    /**
     * CMUX candidate params.
     */
    public static final FusePirCStdKwPirParams CMUX_128_CANDIDATE_PARAMS = new FusePirCStdKwPirParams(
        ParameterSet.CMUX_128_CANDIDATE, 16384, 65537L, new int[0], 3, 40, 16, 3, true,
        FusePirCLweParams.CMUX_128_CANDIDATE, FusePirCCircuitBootstrapParams.CMUX_128_CANDIDATE
    );
    /**
     * Layout fairness candidate params.
     */
    public static final FusePirCStdKwPirParams LAYOUT_16384_CANDIDATE_PARAMS = new FusePirCStdKwPirParams(
        ParameterSet.LAYOUT_16384_CANDIDATE, 16384, 65537L, new int[0], 3, 40, 16, 3,
        true, FusePirCLweParams.LAYOUT_16384_CANDIDATE, FusePirCCircuitBootstrapParams.LAYOUT_16384_CANDIDATE
    );
    /**
     * default params.
     */
    public static final FusePirCStdKwPirParams DEFAULT_PARAMS = new FusePirCStdKwPirParams(
        CMUX_128_CANDIDATE_PARAMS
    );
    /**
     * parameter set.
     */
    private final ParameterSet parameterSet;
    /**
     * poly modulus degree.
     */
    private final int polyModulusDegree;
    /**
     * plain modulus.
     */
    private final long plainModulus;
    /**
     * coeff modulus bits.
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
    private final int valueByteLength;
    /**
     * max value num per keyword.
     */
    private final int maxValueNumPerKeyword;
    /**
     * enable payload split.
     */
    private final boolean enablePayloadSplit;
    /**
     * LWE params.
     */
    private final FusePirCLweParams lweParams;
    /**
     * circuit bootstrap params.
     */
    private final FusePirCCircuitBootstrapParams circuitBootstrapParams;
    /**
     * payload element bit length.
     */
    private final int payloadElementBitLength;
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
     * Previous sqrt-layout row num, kept only for performance log comparison.
     */
    private int oldSqrtMatrixRowNum;
    /**
     * Previous sqrt-layout column num, kept only for performance log comparison.
     */
    private int oldSqrtMatrixColNum;
    /**
     * FUSE_PIR_C raw row packing stride.
     */
    private int rowStride;
    /**
     * payload block num.
     */
    private int payloadBlockNum;
    /**
     * payload blocks packed in one matrix group.
     */
    private int blocksPerPackedMatrix;
    /**
     * packed matrix group num.
     */
    private int packedMatrixGroupNum;
    /**
     * encryption params.
     */
    public byte[] encryptionParams;

    public FusePirCStdKwPirParams(ParameterSet parameterSet, int polyModulusDegree, long plainModulus,
                               int[] coeffModulusBits, int bffHashNum,
                               int fingerprintBitLength, int valueByteLength, int maxValueNumPerKeyword,
                               boolean enablePayloadSplit, FusePirCLweParams lweParams,
                               FusePirCCircuitBootstrapParams circuitBootstrapParams) {
        MathPreconditions.checkPositive("poly_modulus_degree", polyModulusDegree);
        MathPreconditions.checkGreater("plain_modulus", plainModulus, 1L);
        MathPreconditions.checkEqual("bff_hash_num", "3", bffHashNum, 3);
        MathPreconditions.checkPositive("fingerprint_bit_length", fingerprintBitLength);
        MathPreconditions.checkPositive("value_byte_length", valueByteLength);
        MathPreconditions.checkPositive("max_value_num_per_keyword", maxValueNumPerKeyword);
        this.parameterSet = parameterSet;
        this.polyModulusDegree = polyModulusDegree;
        this.plainModulus = plainModulus;
        this.coeffModulusBits = Arrays.copyOf(coeffModulusBits, coeffModulusBits.length);
        this.bffHashNum = bffHashNum;
        this.fingerprintBitLength = fingerprintBitLength;
        this.valueByteLength = valueByteLength;
        this.maxValueNumPerKeyword = maxValueNumPerKeyword;
        this.enablePayloadSplit = enablePayloadSplit;
        this.lweParams = new FusePirCLweParams(lweParams);
        this.circuitBootstrapParams = new FusePirCCircuitBootstrapParams(circuitBootstrapParams);
        payloadElementBitLength = (Long.SIZE - Long.numberOfLeadingZeros(plainModulus - 1)) / Byte.SIZE * Byte.SIZE;
    }

    public FusePirCStdKwPirParams(int fingerprintBitLength, int valueByteLength, int maxValueNumPerKeyword,
                               boolean enablePayloadSplit) {
        this(DEFAULT_PARAMS.parameterSet, fingerprintBitLength, valueByteLength, maxValueNumPerKeyword,
            enablePayloadSplit);
    }

    FusePirCStdKwPirParams(ParameterSet parameterSet, int fingerprintBitLength, int valueByteLength,
                        int maxValueNumPerKeyword, boolean enablePayloadSplit) {
        this(baseParams(parameterSet).parameterSet, baseParams(parameterSet).polyModulusDegree,
            baseParams(parameterSet).plainModulus, baseParams(parameterSet).coeffModulusBits,
            baseParams(parameterSet).bffHashNum, fingerprintBitLength, valueByteLength, maxValueNumPerKeyword,
            enablePayloadSplit, baseParams(parameterSet).lweParams, baseParams(parameterSet).circuitBootstrapParams);
    }

    private static FusePirCStdKwPirParams baseParams(ParameterSet parameterSet) {
        return switch (parameterSet) {
            case RAW_CORRECTNESS -> RAW_CORRECTNESS_PARAMS;
            case CMUX_128_CANDIDATE -> CMUX_128_CANDIDATE_PARAMS;
            case LAYOUT_16384_CANDIDATE -> LAYOUT_16384_CANDIDATE_PARAMS;
        };
    }

    public FusePirCStdKwPirParams(FusePirCStdKwPirParams params) {
        this(params.parameterSet, params.polyModulusDegree, params.plainModulus, params.coeffModulusBits,
            params.bffHashNum,
            params.fingerprintBitLength, params.valueByteLength, params.maxValueNumPerKeyword,
            params.enablePayloadSplit, params.lweParams, params.circuitBootstrapParams);
        bffSlotNum = params.bffSlotNum;
        matrixRowNum = params.matrixRowNum;
        matrixColNum = params.matrixColNum;
        oldSqrtMatrixRowNum = params.oldSqrtMatrixRowNum;
        oldSqrtMatrixColNum = params.oldSqrtMatrixColNum;
        rowStride = params.rowStride;
        payloadBlockNum = params.payloadBlockNum;
        blocksPerPackedMatrix = params.blocksPerPackedMatrix;
        packedMatrixGroupNum = params.packedMatrixGroupNum;
        encryptionParams = params.encryptionParams == null ? null : Arrays.copyOf(params.encryptionParams,
            params.encryptionParams.length);
    }

    public void initPirParams(int keywordNum) {
        MathPreconditions.checkPositive("keyword_num", keywordNum);
        Arity3ByteFusePosition<byte[]> fusePosition = new Arity3ByteFusePosition<>(
            EnvType.STANDARD, keywordNum, getPayloadBlockByteLength(), new byte[16]
        );
        bffSlotNum = fusePosition.filterLength();
        oldSqrtMatrixRowNum = Math.min(circuitBootstrapParams.getRawRlweDegree(),
            (int) Math.ceil(Math.sqrt(bffSlotNum)));
        oldSqrtMatrixColNum = CommonUtils.getUnitNum(bffSlotNum, oldSqrtMatrixRowNum);
        payloadBlockNum = CommonUtils.getUnitNum(getPayloadBitLength(), payloadElementBitLength);
        if (!enablePayloadSplit) {
            MathPreconditions.checkEqual("payload_block_num", "1", payloadBlockNum, 1);
        }
        int rawRlweDegree = circuitBootstrapParams.getRawRlweDegree();
        long oneRawResponseCipherBytes = getOneRawResponseCipherBytes(rawRlweDegree);
        int targetBlocksPerPackedMatrix = Math.max(1,
            (int) ((oneRawResponseCipherBytes + TARGET_RESPONSE_BYTES_PER_PAYLOAD_BLOCK / 2)
                / TARGET_RESPONSE_BYTES_PER_PAYLOAD_BLOCK)
        );
        blocksPerPackedMatrix = Math.min(payloadBlockNum, targetBlocksPerPackedMatrix);
        while (blocksPerPackedMatrix > 1 && rawRlweDegree / blocksPerPackedMatrix < 1) {
            blocksPerPackedMatrix--;
        }
        MathPreconditions.checkPositive("blocks_per_packed_matrix", blocksPerPackedMatrix);
        if (payloadBlockNum > 1) {
            MathPreconditions.checkGreater("blocks_per_packed_matrix", blocksPerPackedMatrix, 1);
        }
        rowStride = blocksPerPackedMatrix;
        matrixRowNum = Math.min(bffSlotNum, rawRlweDegree / blocksPerPackedMatrix);
        MathPreconditions.checkPositive("matrix_row_num", matrixRowNum);
        matrixColNum = CommonUtils.getUnitNum(bffSlotNum, matrixRowNum);
        MathPreconditions.checkLessOrEqual("matrix_row_num", matrixRowNum, polyModulusDegree);
        MathPreconditions.checkLessOrEqual("packed row coefficients", matrixRowNum * blocksPerPackedMatrix,
            rawRlweDegree);
        packedMatrixGroupNum = CommonUtils.getUnitNum(payloadBlockNum, blocksPerPackedMatrix);
        encryptionParams = FusePirCStdKwPirNativeUtils.generateEncryptionParams(
            polyModulusDegree, plainModulus, coeffModulusBits
        );
    }

    private static long getOneRawResponseCipherBytes(int rawRlweDegree) {
        return 2L * rawRlweDegree * Long.BYTES;
    }

    public int getPolyModulusDegree() {
        return polyModulusDegree;
    }

    public ParameterSet getParameterSet() {
        return parameterSet;
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

    public int getOldSqrtMatrixRowNum() {
        return oldSqrtMatrixRowNum;
    }

    public int getOldSqrtMatrixColNum() {
        return oldSqrtMatrixColNum;
    }

    public int getRowStride() {
        return rowStride;
    }

    public int getFingerprintByteLength() {
        return CommonUtils.getByteLength(fingerprintBitLength);
    }

    public int getFingerprintBitLength() {
        return fingerprintBitLength;
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

    public int getLegacyBlocksPerPackedMatrix() {
        return LEGACY_BLOCKS_PER_PACKED_MATRIX;
    }

    public int getTargetResponseBytesPerPayloadBlock() {
        return TARGET_RESPONSE_BYTES_PER_PAYLOAD_BLOCK;
    }

    public long getOneRawResponseCipherBytes() {
        return getOneRawResponseCipherBytes(getRawRlweDegree());
    }

    public int getLegacyPackedMatrixGroupNum() {
        return CommonUtils.getUnitNum(payloadBlockNum, LEGACY_BLOCKS_PER_PACKED_MATRIX);
    }

    public long getExpectedResponseBytes() {
        return (long) packedMatrixGroupNum * getOneRawResponseCipherBytes();
    }

    public long getLegacyExpectedResponseBytes() {
        return (long) getLegacyPackedMatrixGroupNum() * getOneRawResponseCipherBytes();
    }

    public int getPackedMatrixGroupNum() {
        return packedMatrixGroupNum;
    }

    public int getPayloadElementBitLength() {
        return payloadElementBitLength;
    }

    public FusePirCLweParams getLweParams() {
        return new FusePirCLweParams(lweParams);
    }

    public FusePirCCircuitBootstrapParams getCircuitBootstrapParams() {
        return new FusePirCCircuitBootstrapParams(circuitBootstrapParams);
    }

    public int getRawRlweDegree() {
        return circuitBootstrapParams.getRawRlweDegree();
    }

    public long getRawRlweModulus() {
        return circuitBootstrapParams.getRawRlweModulus();
    }

    public String getSecurityLabel() {
        return circuitBootstrapParams.getSecurityLabel();
    }

    public int getPayloadByteLength() {
        return CommonUtils.getByteLength(getPayloadBitLength());
    }

    public int getPayloadBitLength() {
        return fingerprintBitLength + maxValueNumPerKeyword * valueByteLength * Byte.SIZE;
    }

    public int getPayloadBlockByteLength() {
        return CommonUtils.getByteLength(payloadElementBitLength);
    }

    @Override
    public int maxRetrievalSize() {
        return Integer.MAX_VALUE;
    }
}
