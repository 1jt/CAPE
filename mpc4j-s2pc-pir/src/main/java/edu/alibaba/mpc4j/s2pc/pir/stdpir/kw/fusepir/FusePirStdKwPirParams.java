package edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepir;

import edu.alibaba.mpc4j.common.structure.fusefilter.Arity3ByteFusePosition;
import edu.alibaba.mpc4j.common.tool.EnvType;
import edu.alibaba.mpc4j.common.tool.MathPreconditions;
import edu.alibaba.mpc4j.common.tool.utils.CommonUtils;
import edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.StdKwPirParams;

import java.util.Arrays;

/**
 * FUSE_PIR standard keyword PIR params.
 *
 * <p>The first implementation keeps the native matrix entry as one BFV plaintext coefficient. Therefore one payload
 * block contains at most {@code payloadElementBitLength} bits. Large keyword payloads are represented by multiple
 * independent BFF / matrix blocks.</p>
 *
 * @author Weiran Liu
 * @date 2026/06/05
 */
public class FusePirStdKwPirParams implements StdKwPirParams {
    /**
     * default params
     */
    public static final FusePirStdKwPirParams DEFAULT_PARAMS = new FusePirStdKwPirParams(
        16384, 65537L, new int[]{60, 60, 60, 60, 60, 60, 60}, 3, 40, 16, 3, true
    );
    /**
     * poly modulus degree
     */
    private final int polyModulusDegree;
    /**
     * plain modulus
     */
    private final long plainModulus;
    /**
     * coeff modulus bits
     */
    private final int[] coeffModulusBits;
    /**
     * BFF hash num
     */
    private final int bffHashNum;
    /**
     * fingerprint bit length
     */
    private final int fingerprintBitLength;
    /**
     * value byte length
     */
    private final int valueByteLength;
    /**
     * max value num per keyword
     */
    private final int maxValueNumPerKeyword;
    /**
     * enable payload split
     */
    private final boolean enablePayloadSplit;
    /**
     * payload element bit length
     */
    private final int payloadElementBitLength;
    /**
     * BFF slot num
     */
    private int bffSlotNum;
    /**
     * matrix row num
     */
    private int matrixRowNum;
    /**
     * matrix column num
     */
    private int matrixColNum;
    /**
     * payload block num
     */
    private int payloadBlockNum;
    /**
     * payload blocks packed in one matrix group
     */
    private int blocksPerPackedMatrix;
    /**
     * packed matrix group num
     */
    private int packedMatrixGroupNum;
    /**
     * encryption params
     */
    public byte[] encryptionParams;

    public FusePirStdKwPirParams(int polyModulusDegree, long plainModulus, int[] coeffModulusBits, int bffHashNum,
                              int fingerprintBitLength, int valueByteLength, int maxValueNumPerKeyword,
                              boolean enablePayloadSplit) {
        MathPreconditions.checkPositive("poly_modulus_degree", polyModulusDegree);
        MathPreconditions.checkGreater("plain_modulus", plainModulus, 1L);
        MathPreconditions.checkEqual("bff_hash_num", "3", bffHashNum, 3);
        MathPreconditions.checkPositive("fingerprint_bit_length", fingerprintBitLength);
        MathPreconditions.checkPositive("value_byte_length", valueByteLength);
        MathPreconditions.checkPositive("max_value_num_per_keyword", maxValueNumPerKeyword);
        this.polyModulusDegree = polyModulusDegree;
        this.plainModulus = plainModulus;
        this.coeffModulusBits = Arrays.copyOf(coeffModulusBits, coeffModulusBits.length);
        this.bffHashNum = bffHashNum;
        this.fingerprintBitLength = fingerprintBitLength;
        this.valueByteLength = valueByteLength;
        this.maxValueNumPerKeyword = maxValueNumPerKeyword;
        this.enablePayloadSplit = enablePayloadSplit;
        // Each BFF share is stored as one Z_p coefficient. Use the largest whole-byte payload that safely fits in
        // the plaintext modulus. For p = 65537, this packs 2 bytes per coefficient instead of 1 byte per coefficient.
        payloadElementBitLength = (Long.SIZE - Long.numberOfLeadingZeros(plainModulus - 1)) / Byte.SIZE * Byte.SIZE;
    }

    public FusePirStdKwPirParams(int fingerprintBitLength, int valueByteLength, int maxValueNumPerKeyword,
                              boolean enablePayloadSplit) {
        this(DEFAULT_PARAMS.polyModulusDegree, DEFAULT_PARAMS.plainModulus, DEFAULT_PARAMS.coeffModulusBits,
            DEFAULT_PARAMS.bffHashNum, fingerprintBitLength, valueByteLength, maxValueNumPerKeyword,
            enablePayloadSplit);
    }

    public FusePirStdKwPirParams(FusePirStdKwPirParams params) {
        this(params.polyModulusDegree, params.plainModulus, params.coeffModulusBits, params.bffHashNum,
            params.fingerprintBitLength, params.valueByteLength, params.maxValueNumPerKeyword,
            params.enablePayloadSplit);
        bffSlotNum = params.bffSlotNum;
        matrixRowNum = params.matrixRowNum;
        matrixColNum = params.matrixColNum;
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
        matrixRowNum = Math.min(polyModulusDegree, (int) Math.ceil(Math.sqrt(bffSlotNum)));
        matrixColNum = CommonUtils.getUnitNum(bffSlotNum, matrixRowNum);
        MathPreconditions.checkLessOrEqual("matrix_row_num", matrixRowNum, polyModulusDegree);
        payloadBlockNum = CommonUtils.getUnitNum(getPayloadByteLength(), getPayloadBlockByteLength());
        if (!enablePayloadSplit) {
            MathPreconditions.checkEqual("payload_block_num", "1", payloadBlockNum, 1);
        }
        int maxBlocksPerPackedMatrix = polyModulusDegree / (matrixRowNum * matrixColNum);
        blocksPerPackedMatrix = Math.min(payloadBlockNum, maxBlocksPerPackedMatrix);
        MathPreconditions.checkPositive("blocks_per_packed_matrix", blocksPerPackedMatrix);
        packedMatrixGroupNum = CommonUtils.getUnitNum(payloadBlockNum, blocksPerPackedMatrix);
        encryptionParams = FusePirStdKwPirNativeUtils.generateEncryptionParams(
            polyModulusDegree, plainModulus, coeffModulusBits
        );
    }

    public int getPolyModulusDegree() {
        return polyModulusDegree;
    }

    public long getPlainModulus() {
        return plainModulus;
    }

    public int getPlainModulusBitLength() {
        return Long.SIZE - Long.numberOfLeadingZeros(plainModulus - 1) - 1;
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

    public int getPackedMatrixGroupNum() {
        return packedMatrixGroupNum;
    }

    public int getPayloadElementBitLength() {
        return payloadElementBitLength;
    }

    public boolean isEnablePayloadSplit() {
        return enablePayloadSplit;
    }

    public int getPayloadByteLength() {
        return getFingerprintByteLength() + valueByteLength * maxValueNumPerKeyword;
    }

    public int getPayloadBlockByteLength() {
        return CommonUtils.getByteLength(payloadElementBitLength);
    }

    @Override
    public int maxRetrievalSize() {
        return Integer.MAX_VALUE;
    }
}
