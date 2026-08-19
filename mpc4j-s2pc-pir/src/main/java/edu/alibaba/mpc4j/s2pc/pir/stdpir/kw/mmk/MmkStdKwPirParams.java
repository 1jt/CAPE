package edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.mmk;

import edu.alibaba.mpc4j.common.tool.MathPreconditions;
import edu.alibaba.mpc4j.common.tool.utils.CommonUtils;
import edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.StdKwPirParams;

import java.util.Arrays;

/**
 * MMK standard keyword PIR params.
 *
 * @author Weiran Liu
 * @date 2026/06/04
 */
public class MmkStdKwPirParams implements StdKwPirParams {
    /**
     * default params
     */
    public static final MmkStdKwPirParams DEFAULT_PARAMS = new MmkStdKwPirParams(
        16384, 65537L, new int[0], 8
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
     * constant weight k
     */
    private final int cwWeight;
    /**
     * codeword length w. We use one BFV coefficient per codeword coordinate, so w defaults to the full polynomial
     * degree. This keeps the stage-2 encoding direct and leaves batching/slot packing optimizations to later stages.
     */
    private final int codewordLength;
    /**
     * payload coefficient num
     */
    public int payloadCoeffNum;
    /**
     * payload coefficient num per plaintext
     */
    public int payloadCoeffNumPerPlaintext;
    /**
     * payload plaintext num
     */
    public int payloadPlaintextNum;
    /**
     * encryption params
     */
    public byte[] encryptionParams;

    public MmkStdKwPirParams(int polyModulusDegree, long plainModulus, int[] coeffModulusBits, int cwWeight) {
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

    public int getPlainModulusBitLength() {
        return Long.SIZE - Long.numberOfLeadingZeros(plainModulus - 1) - 1;
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
     * @param n              database size.
     * @param labelBitLength label bit length.
     */
    public void initPirParams(int n, int labelBitLength) {
        MathPreconditions.checkPositive("n", n);
        MathPreconditions.checkPositive("label_bit_length", labelBitLength);
        MathPreconditions.checkLessOrEqual("n", n, maxRetrievalSize());
        payloadCoeffNum = CommonUtils.getUnitNum(labelBitLength, getPlainModulusBitLength());
        payloadCoeffNumPerPlaintext = Math.min(payloadCoeffNum, polyModulusDegree);
        payloadPlaintextNum = CommonUtils.getUnitNum(payloadCoeffNum, polyModulusDegree);
        encryptionParams = MmkStdKwPirNativeUtils.generateEncryptionParams(
            polyModulusDegree, plainModulus, coeffModulusBits
        );
    }

    @Override
    public int maxRetrievalSize() {
        return Integer.MAX_VALUE;
    }

    @Override
    public String toString() {
        return
            " Encryption parameters: {" + "\n" +
            "     - plain_modulus : " + getPlainModulus() + "\n" +
            "     - plain_modulus_bit_length : " + getPlainModulusBitLength() + "\n" +
            "     - poly_modulus_degree : " + getPolyModulusDegree() + "\n" +
            "     - coeff_modulus : SEAL BFVDefault(tc128)" + "\n" +
            "     - cw_weight : " + getCwWeight() + "\n" +
            "     - codeword_length : " + getCodewordLength() + "\n" +
            "  }" + "\n";
    }
}
