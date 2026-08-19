package edu.alibaba.mpc4j.s2pc.pir.conpir.bkpir;

import edu.alibaba.mpc4j.common.tool.MathPreconditions;
import edu.alibaba.mpc4j.common.tool.utils.CommonUtils;

import java.util.Arrays;

/**
 * BKPIR params.
 *
 * @author Weiran Liu
 * @date 2026/06/05
 */
public class BkPirParams {
    /**
     * default params.
     */
    public static final BkPirParams DEFAULT_PARAMS = new BkPirParams(
        16384, 65537L, new int[0], 8
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
     * coeff modulus bits.
     */
    private final int[] coeffModulusBits;
    /**
     * constant weight.
     */
    private final int cwWeight;
    /**
     * codeword length. We use one BFV slot / coefficient per coordinate in the first BKPIR implementation.
     */
    private final int codewordLength;
    /**
     * value space size.
     */
    public int valueSpaceSize;
    /**
     * value byte length.
     */
    public int valueByteLength;
    /**
     * payload plaintext num. The first real-payload BKPIR implementation stores one value byte in one BFV plaintext.
     */
    public int payloadPlaintextNum;
    /**
     * value byte num per payload plaintext.
     */
    public int valueByteNumPerPayloadPlaintext;
    /**
     * payload plaintext num per value space chunk.
     */
    public int payloadPlaintextNumPerChunk;
    /**
     * value space chunk num.
     */
    public int valueChunkNum;
    /**
     * encryption params.
     */
    public byte[] encryptionParams;

    public BkPirParams(int polyModulusDegree, long plainModulus, int[] coeffModulusBits, int cwWeight) {
        MathPreconditions.checkPositive("poly_modulus_degree", polyModulusDegree);
        MathPreconditions.checkGreater("plain_modulus", plainModulus, 1L);
        MathPreconditions.checkPositiveInRangeClosed("cw_weight", cwWeight, polyModulusDegree);
        this.polyModulusDegree = polyModulusDegree;
        this.plainModulus = plainModulus;
        this.coeffModulusBits = Arrays.copyOf(coeffModulusBits, coeffModulusBits.length);
        this.cwWeight = cwWeight;
        codewordLength = polyModulusDegree;
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

    public int getCwWeight() {
        return cwWeight;
    }

    public int getCodewordLength() {
        return codewordLength;
    }

    public byte[] getEncryptionParams() {
        return encryptionParams;
    }

    /**
     * initialize PIR params.
     *
     * @param keywordNum     keyword num.
     * @param valueSpaceSize value space size.
     */
    public void initPirParams(int keywordNum, int valueSpaceSize, int valueByteLength) {
        MathPreconditions.checkPositive("keyword_num", keywordNum);
        MathPreconditions.checkPositive("value_space_size", valueSpaceSize);
        MathPreconditions.checkPositive("value_byte_length", valueByteLength);
        this.valueSpaceSize = valueSpaceSize;
        this.valueByteLength = valueByteLength;
        valueChunkNum = CommonUtils.getUnitNum(valueSpaceSize, polyModulusDegree);
        valueByteNumPerPayloadPlaintext = Math.max(1, (Long.SIZE - Long.numberOfLeadingZeros(plainModulus - 2L)) / Byte.SIZE);
        payloadPlaintextNumPerChunk = CommonUtils.getUnitNum(valueByteLength, valueByteNumPerPayloadPlaintext);
        payloadPlaintextNum = payloadPlaintextNumPerChunk * valueChunkNum;
        encryptionParams = BkPirNativeUtils.generateEncryptionParams(
            polyModulusDegree, plainModulus, coeffModulusBits
        );
    }

    /**
     * initialize PIR params.
     *
     * @param keywordNum      keyword num.
     * @param valueSpaceSize  value space size.
     * @param valueBitLength  value bit length.
     */
    public void initPirParamsByValueBitLength(int keywordNum, int valueSpaceSize, int valueBitLength) {
        MathPreconditions.checkEqual("value_bit_length % Byte.SIZE", "0", valueBitLength % Byte.SIZE, 0);
        initPirParams(keywordNum, valueSpaceSize, CommonUtils.getByteLength(valueBitLength));
    }

    /**
     * max retrieval size.
     *
     * @return max retrieval size.
     */
    public int maxRetrievalSize() {
        return Integer.MAX_VALUE;
    }
}
